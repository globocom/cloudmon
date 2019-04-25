# -*- coding: utf-8 -*-


import threading
import json

import zmq

from cloudmon.connector.cloudstack import CloudStackConnector
from cloudmon.connector.ec2 import EC2Connector
from cloudmon.utils.log import logging


class MessageQueue():

    def __init__(self, config):
        self.config = config
        self.connectors = {
            'cloudstack': CloudStackConnector(config),
            'ec2': EC2Connector(config),
        }
        self.socket = None
        self.threads = []

        self.logger = logging.getLogger('cloudmon.queue')

    def _recv_message(self):
        if self.socket is None:
            return None
        message = self.socket.recv_pyobj()
        self.logger.debug('received request: [%s]' % str(message))
        if not isinstance(message, list) or len(message) < 2:
            self.logger.warning('bad message: [%s]' % str(message))
            return None
        driver = message[0]
        zabbix_hostname = message[1]
        if len(message) > 2:
            try:
                params = {'command': message[2]}
            except ValueError, e:
                self.logger.warning("%s: %s" % (str(e), message[2]))
                params = {}
        else:
            params = {}
        return {"driver": driver, "zabbix_hostname": zabbix_hostname, "params": params}

    def bind(self, listen_address="127.0.0.1", listen_port=5555, max_queue_size=100):
        context = zmq.Context()
        socket = context.socket(zmq.PULL)
        try:
            socket.setsockopt(zmq.HWM, max_queue_size)
        except AttributeError:
            socket.setsockopt(zmq.SNDHWM, max_queue_size)
            socket.setsockopt(zmq.RCVHWM, max_queue_size)
        try:
            socket.bind("tcp://%s:%s" % (listen_address, listen_port))
            self.socket = socket
            self.logger.info("ZMQ Bind Successful! Waiting for requests on port %s" % listen_port )
        except Exception as e:
            self.logger.error("Failed to bind ZeroMQ socket: %s" % str(e))
            socket.close()
            raise

    def poll(self):
        self.logger.info("polling...")
        msg = self._recv_message()
        if msg is None:
            return
        command = msg['params'].get('command', 'api')
        thread_name = "%s-%s" % (msg["zabbix_hostname"], command)
        self.prepare_thread(thread_name, msg)

    def prepare_thread(self, thread_name, msg):
        self.logger.debugv('Preparing Thread: %s => %s', thread_name, msg)
        alive_thread_names = []
        for thread in self.threads:
            if thread.isAlive():
                alive_thread_names.append(thread.name)
            else:
                self.threads.remove(thread)
        if thread_name in alive_thread_names:
            self.logger.debug("Thread %s already running. skipped." % thread_name)
        elif msg["driver"] in self.connectors:
            self.logger.debug("Starting %s thread..." % thread_name)
            th = threading.Thread(name=thread_name, target=self.connectors[msg["driver"]],
                                  kwargs={"hostname": msg["zabbix_hostname"], "params": msg["params"]})
            th.start()
            self.threads.append(th)
        else:
            self.logger.warning("'%s' driver is not supported" % str(msg["driver"]))
        self.logger.debug("Active threads: %s" % [{thread.name: thread.isAlive()} for thread in self.threads])


    def close(self):
        self.logger.info("SystemExit")
        if self.socket is not None:
            self.socket.close()
            self.socket = None
        for thread in self.threads:
            # Bad practice. but no idea
            thread._Thread__stop()
