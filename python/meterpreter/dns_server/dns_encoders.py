#!/usr/bin/env python
# coding=utf-8

# MSF Bridge for reverse_dns transport
#
# Authors: Maxim Andreyanov, Alexey Sintsov
#

from utils import *
import struct


try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)


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
    def encode_registration(client_id, status):
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


class DNSKeyEncoder(Encoder):
    HEADER_SIZE = 4 + 3 # 4 bytes dnskey header, 1 byte for status, 2 for data length
    MAX_PACKET_SIZE = 16384
    ALGO = 253
    PROTOCOL = 3
    FLAGS = 257

    @staticmethod
    def _encode_to_dnskey(key=""):
        return DNSKEY(flags=DNSKeyEncoder.FLAGS, protocol=DNSKeyEncoder.PROTOCOL,
                      algorithm=DNSKeyEncoder.ALGO, key=key)

    @staticmethod
    def _encode_data(status=0, data=""):
        data_len = len(data)
        return struct.pack("<BH", status, data_len) + data

    @staticmethod
    def encode_data_header(sub_domain, data_size):
        key_data = struct.pack("4sI", sub_domain, data_size)
        key = DNSKeyEncoder._encode_data(data=key_data)
        return [DNSKeyEncoder._encode_to_dnskey(key)]

    @staticmethod
    def encode_packet(packet_data):
        data_len = len(packet_data)
        if data_len > DNSKeyEncoder.MAX_PACKET_SIZE:
            raise ValueError("Data length is bigger than maximum packet size")
        key = DNSKeyEncoder._encode_data(data=packet_data)
        return [DNSKeyEncoder._encode_to_dnskey(key)]

    @staticmethod
    def encode_ready_receive():
        key = DNSKeyEncoder._encode_data()
        return [DNSKeyEncoder._encode_to_dnskey(key)]

    @staticmethod
    def encode_finish_send():
        key = DNSKeyEncoder._encode_data(status=0x01)
        return [DNSKeyEncoder._encode_to_dnskey(key)]

    @staticmethod
    def encode_send_more_data():
        key = DNSKeyEncoder._encode_data(status=0x00)
        return [DNSKeyEncoder._encode_to_dnskey(key)]

    @staticmethod
    def encode_registration(client_id, status):
        key = DNSKeyEncoder._encode_data(status, client_id)
        return [DNSKeyEncoder._encode_to_dnskey(key)]


class NULLEncoder(Encoder):
    pass
