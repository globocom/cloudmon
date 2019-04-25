# -*- coding: utf-8 -*-

"""
Classes for defining, connecting and consuming AWS EC2 event queue
"""


import re
import json
import traceback
import time

import pika

# from .base import BaseConnector
from cloudmon.connector.base import BaseConnector
from cloudmon.utils.log import logging
from cloudmon.connector.errors import CacheMiss, CacheError
# from errors import CacheMiss, CacheError


def get_last_msg_ec2():
    return 0


class EC2Queue(BaseConnector):
    '''Class for defining, connecting and consuming AWS EC2 event queue'''


    RUNNING_KEY = 'aws.compute.instance.running'
    STOPPED_KEY = 'aws.compute.instance.stopped'
    TERMINATED_KEY = 'aws.compute.instance.terminated'
    CREATE_TAGS = 'aws.compute.instance.createtags'
    DELETE_TAGS = 'aws.compute.instance.deletetags'

    ROUTING_KEYS = [
        RUNNING_KEY, STOPPED_KEY, TERMINATED_KEY, CREATE_TAGS, DELETE_TAGS
    ]

    def __init__(self, owner, params, config):
        super(EC2Queue, self).__init__(config)
        # self.zabbix_api = zabbix_api
        self.type = 'ec2'
        self.config = config

        self.logger = logging.getLogger('cloudmon.ec2.queue')
        self.owner = owner
        if config['logging']['queue_log_file']:
            self.logger_queue = logging.getLogger('cloudstack_queue')
        else:
            self.logger_queue = False

        self.queue = params.get('queue', '')
        self.exchange = params.get('exchange', '')
        self.queue_creates = 0
        self.queue_updates = 0
        self.queue_deletes = 0
        params = pika.URLParameters(params['url'])

        for i in range(11):  # Almost never connects at first attempt
            try:
                channel = pika.BlockingConnection(params).channel()
                self.logger.info('Connected to the AWS EC2 Event Queue at %s attempt' %(i+1) )
                break
            except pika.exceptions.ConnectionClosed:
                if i > 9:
                    self.logger.error('Failed to to connect to the AWS EC2 Event Queue.')
                    self.logger.error(traceback.format_exc())
                    return None
        try:
            for i in self.ROUTING_KEYS:
                channel.queue_bind(
                    exchange=self.exchange,
                    queue=self.queue,
                    routing_key=i
                )
                self.logger.info('The following bind will be consumed: [%s, %s, %s]' % (self.exchange, self.queue, i) )
            self.channel = channel
        except Exception:
            self.logger.error('Failed to create binds to the AWS EC2 Queue with params [%s, %s, %s]' % (self.exchange, self.queue, str(self.ROUTING_KEYS)))
            self.logger.error(traceback.format_exc())
            return None

    def callback(self, ch, method, properties, body):
        try:
            if self.logger_queue:
                self.logger_queue.info('%s:%s' % (method.routing_key, body))

            body = json.loads(body)
            node = self.make_node(body)
            tag = body.get('EventTags', {})
            valid_tag = tag and isinstance(tag, dict)

            if method.routing_key == self.CREATE_TAGS and valid_tag:
                self.logger.debug(
                    'New tag {%s:%s} detected in %s / %s',
                    tag['key'],
                    tag['value'],
                    node['id'],
                    node['name'],
                )
                self.assign_tag_zbx(
                    self.owner,
                    node,
                    tag['key'],
                    tag['value'],
                )

            elif method.routing_key == self.DELETE_TAGS and valid_tag:
                self.logger.debug(
                    'The tag {%s:%s} was removed from %s / %s',
                    tag['key'],
                    tag['value'],
                    node['id'],
                    node['name'],
                )
                self.assign_tag_zbx(
                    self.owner,
                    node,
                    tag['key'],
                    tag['value'],
                    delete_tag=True
                )

            elif self.get_monitoring_tag(node):
                if method.routing_key == self.RUNNING_KEY:
                    if self.get_zabbix_host(node['id']):
                        self.update_status_zbx_from_cs(
                            node['id'], node['state']
                        )
                    else:
                        self.create_zabbix_host(self.owner, node['id'], node)

                elif method.routing_key == self.STOPPED_KEY:
                    self.update_status_zbx_from_cs(
                        node['id'], node['state']
                    )
                elif method.routing_key == self.TERMINATED_KEY:
                    self.delete_zabbix_node(self.owner, node)

        except Exception:
            self.logger.error(traceback.format_exc())
            self.logger.error('Callback failed.')
            return None

    def process(self):
        self.logger.debug('Starting to process the AWS EC2 Event Queue...')
        self.channel.basic_consume(self.callback, queue=self.queue, no_ack=True)
        self.channel.start_consuming()

    def assign_tag_zbx(self, owner, node, key, value, delete_tag=False):
        hostname = node['id']
        (tags, aggregator) = self.validate_tag(key, value, owner)
        if not tags:
            self.logger.debug('Tag is not valid or activated. Nothing to do')
            return False
        params = {
            'filter': {'host': hostname},
            'output': ['hostid', 'name', 'host'],
            'selectGroups': ['groupid'],
            'selectParentTemplates': ['templateid'],
            'selectMacros': ['macro', 'value'],
        }
        host = self.zabbix_api.host.get(**params)
        if host:
            host = host[0]
            # tag created and existing host
            if not delete_tag:
                # cs_vars not available
                self.update_zbx_from_tag(owner, host, tags, aggregator)
                self.queue_updates += 1
            # tag removed and existing host
            else:
                # monitoring tag removed and no monitoring tag left
                if int(tags.get('monitoring', 0)) and not self.get_monitoring_tag(node):
                    self.delete_zbx_host_simple(owner, host)
                    self.queue_deletes += 1
                else:
                    self.update_zbx_from_tag(owner, host, tags, aggregator, delete_tag=True)
                    self.queue_updates += 1
        else:
            # Non existing host and monitoring tag created
            if (int(tags.get('monitoring', 0)) and not delete_tag) or self.get_monitoring_tag(node):
                self.logger.debug('Host %s will be created in Zabbix, its monitoring tag is activated.' % hostname)
                self.create_zabbix_host(owner, hostname, node)
                self.queue_creates += 1

            else:
                self.logger.debug('Node %s will not be checked.' % hostname)


    def make_node(self, body):
        if body.get('Instance_Name'):
            name = body.get('Instance_Name') + '_' +  body['ID_Instance']
        else:
            name = body['ID_Instance']

        return {
            'id': body['ID_Instance'],
            'name': name,
            'role': 'EC2_INSTANCE',
            'private_ip_address': body.get('IP_Private'),
            'state': body.get('Instance_State'),
            'tags': [{'key': i['Key'], 'value': i['Value']} for i in body.get('Instance_Tags', [])]
        }
