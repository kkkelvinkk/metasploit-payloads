#!/usr/bin/env python
# coding=utf-8

# MSF Bridge for reverse_dns transport
#
# Authors: Maxim Andreyanov, Alexey Sintsov
#

from contextlib import contextmanager


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