#!/usr/bin/env python
# coding=utf-8

# MSF Bridge for reverse_dns transport
#
# Authors: Maxim Andreyanov, Alexey Sintsov
#

import logging
import re
from dns_client import Client, Registrator

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
            client.update_last_request_ts()
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
