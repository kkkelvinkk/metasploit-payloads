#!/usr/bin/env python
# coding=utf-8

# MSF Bridge for reverse_dns transport
#
# Authors: Maxim Andreyanov, Alexey Sintsov
#

import socket
import select
import logging
import struct
import threading
import os
from dns_client import Registrator
from utils import PartedData, xor_bytes, ignored


class PartedDataReader(object):
    INITIAL = 1
    RECEIVING_DATA = 2

    def __init__(self, read_func, header_func=None, completion_func=None,
                 continue_func=None, init_data=None):
        self.read_func = read_func
        self.header_func = header_func
        self.completion_func = completion_func
        self.continue_func = continue_func
        self.state = PartedDataReader.INITIAL
        self.header = ""
        self.data = init_data

    def read(self):
        if self.state == PartedDataReader.INITIAL:
            data_size, data = self.header_func(self.header)
            if data_size == 0:
                return
            elif data_size == -1:
                self.header = data
                return
            self.header = ""
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
    LOGGER = logging.getLogger("MSFClient")

    def __init__(self, sock, server):
        # enable keep-alive every minute
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 60)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, 4)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 15)
        sock.setblocking(False)
        self.sock = sock
        self.server = server
        self.msf_id = ""
        self.client = None
        self.wait_client = False
        self.stage_requested = False
        self.lock = threading.Lock()
        self.client_event = threading.Event()
        self.parted_reader = None
        self._setup_id_reader()

    def get_socket(self):
        return self.sock if not self.wait_client else None

    def _on_closing_connection(self):
        if self.client:
            client_id = self.client.get_id()
            if client_id:
                MSFClient.LOGGER.info("Unregister client with id %s", client_id)
                Registrator.instance().unregister_client(client_id)
            self.client.set_server(None)
            self.client = None
        Registrator.instance().unsubscribe(self.msf_id, self)
        self.close()
        self.server.remove_me(self)

    def _read_data(self, size):
        data = None
        try:
            data = self.sock.recv(size)
            if not data:
                MSFClient.LOGGER.info("Connection closed by msf")
                self._on_closing_connection()
                return None
            return data
        except:
            # connection closed
            MSFClient.LOGGER.error("Exception during read. Closing connection.", exc_info=True)
            self._on_closing_connection()
            return None

    def on_new_client(self):
        with self.lock:
            if not self.client:
                if self._setup_client():
                    self._setup_status_request_reader()
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
    
    def _setup_status_request_reader(self):
        self.parted_reader = PartedDataReader(read_func=self._read_data,
                                              header_func=self._read_status_request,
                                              completion_func=self._read_status_complete
                                              )

    def _read_id_header(self, data):
        id_size_byte = self._read_data(1)
        if id_size_byte and len(id_size_byte) == 1:
            id_size = struct.unpack("B", id_size_byte)[0]
            return id_size, None
        else:
            return 0, None

    def _read_id_complete(self, data):
        MSFClient.LOGGER.info("Id read is done")
        self.msf_id = data.get_data()
        if self._setup_client():
            MSFClient.LOGGER.info("New client is found.")
            self._setup_status_request_reader()
        else:
            MSFClient.LOGGER.info("There are no clients for server id %s. Create subscription",
                                  self.msf_id)
            self.parted_reader = None
            self.wait_client = True
            Registrator.instance().subscribe(self.msf_id, self)

    def _read_stage_header(self, data):
        MSFClient.LOGGER.info("Start reading stager")
        data_size_b = self._read_data(4)
        if data_size_b and len(data_size_b) == 4:
            data_size = struct.unpack("<I", data_size_b)[0]
            MSFClient.LOGGER.info("Stager size is %d bytes", data_size)
            return data_size+4, data_size_b
        else:
            return 0, None

    def _read_stage_complete(self, data):
        MSFClient.LOGGER.info("Stage read is done")
        Registrator.instance().add_stager_for_server(self.msf_id, data.get_data())
        self._setup_status_request_reader()

    def _read_status_request(self, data):
        MSFClient.LOGGER.info("Start reading status request")
        data_size = 1
        return data_size, None

    def _read_status_complete(self, data):
        MSFClient.LOGGER.info("Status request is read")
        if self.client:
            MSFClient.LOGGER.info("Client is exists, send true")
            self.sock.send("\x01")
            self._setup_tlv_reader()
        elif self._setup_client():
            MSFClient.LOGGER.info("New client is found, send true")
            self.sock.send("\x01")
            self._setup_tlv_reader()
            self.wait_client = False
        else:
            MSFClient.LOGGER.info("There are no clients, send false")
            self.sock.send("\x00")

    def _read_stage_complete_data_drop(self, data):
        MSFClient.LOGGER.info("Stage read is done. Drop data and continue.")
        if self._setup_client():
            MSFClient.LOGGER.info("Client is found.Setup tlv reader.")
            self._setup_tlv_reader()
        else:
            MSFClient.LOGGER.info("There are no clients for server id %s. Create subscription", self.msf_id)
            self.parted_reader = None
            self.wait_client = True
            Registrator.instance().subscribe(self.msf_id, self)

    def _read_tlv_header(self, data):
        header = self._read_data(MSFClient.HEADER_SIZE - len(data))
        if not header:
            return 0, None

        header = data + header
        if len(header) != MSFClient.HEADER_SIZE:
            MSFClient.LOGGER.info("Can't read full header(%s - %d)", self.sock, len(header))
            return -1, header

        if len(data) != 0:
            MSFClient.LOGGER.info("Full header is read succesfully(%s)", self.sock)
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
            MSFClient.LOGGER.error("There are no msf id!!!")
            return False
        client = Registrator.instance().get_new_client_for_server(self.msf_id)
        if client:
            self.client = client
            client.set_server(self)
            MSFClient.LOGGER.info("Association client-server is done successfully(%s(%s)<->%s)",
                                   self.msf_id, str(self), self.client.get_id())
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
                self.sock.send(data)

    def close(self):
        self.sock.close()
        self.sock = None

    def on_client_timeout(self):
        MSFClient.LOGGER.info("Closing connection.(client timeout)")
        self.client = None
        self.server.remove_me(self)
        self.close()
        self.polling()


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
