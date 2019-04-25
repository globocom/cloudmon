# -*- coding: utf-8 -*-

"""
Classes for defining, connecting and consuming CloudStack event queue
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

def get_last_msg_cs():
    return 0


class CloudStackQueue(BaseConnector):
    '''Class for defining, connecting and consuming CloudStack event queue'''

    ROUTING_KEYS = [
        'management-server.ResourceStateEvent.OperationSucceeded.VirtualMachine.*',
        'management-server.AsyncJobEvent.complete.*.*',
        'management-server.ResourceStateEvent.FollowAgentPowerOffReport.VirtualMachine.*'

    ]

    RE_STATUS = r'^management\-server\.ResourceStateEvent\.OperationSucceeded\.VirtualMachine\.'
    RE_TAGS = r'^management\-server\.AsyncJobEvent\.complete\.None\.*'
    # RE_VM = r'^management\-server\.AsyncJobEvent\.complete\.VirtualMachine\.*'
    # RE_ROUTER = r'^management\-server\.AsyncJobEvent\.complete\.DomainRouter\.*'
    # RE_SVM = r'^management\-server\.AsyncJobEvent\.complete\.SystemVm\.*'
    RE_COMPLETE = r'^management\-server\.AsyncJobEvent\.complete\.(VirtualMachine|DomainRouter|SystemVm)\.*'

    ST_OK = 'SUCCEEDED'
    ST_READY = 'postStateTransitionEvent'

    def __init__(self, owner, params, config, cs_api):
        super(CloudStackQueue, self).__init__(config)
        # self.zabbix_api = zabbix_api
        self.type = 'cloudstack'
        self.config = config

        self.logger = logging.getLogger('cloudmon.cloudstack.queue')
        self.owner = owner
        self.cs_api = cs_api
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
                self.logger.info('Connected to the CloudStack Event Queue at %s attempt' %(i+1) )
                break
            except pika.exceptions.ConnectionClosed:
                if i > 9:
                    self.logger.error('Failed to to connect to the CloudStack Event Queue.')
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
            self.logger.error('Failed to create binds to the CloudStack Event Queue with params [%s, %s, %s]' % (self.exchange, self.queue, str(self.ROUTING_KEYS)))
            self.logger.error(traceback.format_exc())
            return None

    def callback(self, ch, method, properties, body):
        try:
            if self.logger_queue:
                self.logger_queue.info('%s:%s' % (method.routing_key, body))

            body = json.loads(body)
            key_status = re.match(self.RE_STATUS, method.routing_key)
            key_tags = re.match(self.RE_TAGS, method.routing_key)
            key_async = re.match(self.RE_COMPLETE, method.routing_key)
            st_ready = body.get('status') == self.ST_READY
            st_ok = body.get('status') == self.ST_OK
            create_tags = body.get('commandEventType') == 'CREATE_TAGS'
            delete_tags = body.get('commandEventType') == 'DELETE_TAGS'


            if key_status and st_ready:
                if self.get_monitoring_by_id(body['id']):
                    self.logger.debug(
                        'Change of staus for %s from %s to %s detected via '
                        'ResourceStateEvent.OperationSucceeded.',
                        body['id'], body['old-state'], body['new-state']
                    )
                    self.update_status_zbx_from_cs(body['id'], body['new-state'])
                    self.queue_updates += 1

                    if body.get('resource') in ['VirtualMachine', 'DomainRouter', 'SystemVm']:
                        self.cache.update_status(
                            self.owner,
                            body['resource'],
                            body['id'],
                            body['new-state']
                        )

            elif key_tags and st_ok and create_tags:
                node = json.loads(body.get('cmdInfo', '{}'))
                if node:
                    ids = node.get('resourceIds', node.get('resourceids', []))
                    if ids:
                        ids = ids.split(',')
                    for id_ in ids:
                        self.logger.debug(
                            'New tag {%s:%s} detected in %s',
                            node['tags[0].key'],
                            node['tags[0].value'],
                            id_
                        )
                        self.assign_tag_zbx(
                            self.owner,
                            id_,
                            node['tags[0].key'],
                            node['tags[0].value']
                        )
            elif key_tags and st_ok and delete_tags:
                node = json.loads(body.get('cmdInfo', '{}'))
                if node:
                    ids = node.get('resourceIds', node.get('resourceids', []))
                    if ids:
                        ids = ids.split(',')
                    for id_ in ids:
                        self.logger.debug(
                            'The tag {%s:%s} was removed from %s',
                            node['tags[0].key'],
                            node['tags[0].value'],
                            id_
                        )
                        self.assign_tag_zbx(
                            self.owner,
                            id_,
                            node['tags[0].key'],
                            node['tags[0].value'],
                            delete_tag=True
                        )

            elif key_async and st_ok:
                found_ptrn = re.match(r'^.*/({.*$)', body.get('jobResult', ''))
                if found_ptrn:
                    node = json.loads(found_ptrn.groups()[0])
                    if not node.get('id'):
                        cmdinfo = json.loads(body.get('cmdInfo', '{}'))
                        node['id'] = cmdinfo.get('id', '')
                        if re.match(r'^.+\.DESTROY', body.get('commandEventType', '')):
                            node['tags'] = [{'key':'monitoring', 'value':'1'}]
                    node['name'] = node.get('name', '')
                    node['role'] = self.role_to_instance_type(body.get('instanceType', ''))

                    if not node['role']:
                        self.logger.debug('Type not supported, skipping...')
                        return None
                    if not node['id']:
                        self.logger.debug('Id not found, skipping...')
                        return None

                    if self.get_monitoring_tag(node):
                        self.logger.debug('%s event found for %s(%s) ' % (body['commandEventType'], node['name'], node['id']))

                        if re.match(r'^.+\.CREATE', body.get('commandEventType', '')):
                            self.logger.debug('Host %s(%s) will be created in Zabbix, its monitoring tag is activated.' % (node['name'], node['id']))
                            self.create_zabbix_host(self.owner, node['id'], node)
                            self.queue_creates += 1

                        elif re.match(r'^.+\.DESTROY', body.get('commandEventType', '')):
                            self.logger.debug('Host %s(%s) will be removed from Zabbix.' % (node['name'], node['id']))
                            self.delete_zabbix_node(self.owner, node)
                            self.queue_deletes += 1

                        # elif re.match(r'^.+\.(START|STOP)', body.get('commandEventType', '')):
                        #     self.logger.debug('Change of status for %s to %s detected.' % (node['id'], node['state']))
                        #     self.update_status_zbx_from_cs(node['id'], node['state'])
                        #     self.queue_updates += 1
                    else:
                        self.logger.debug('Host %s(%s) will not be checked, its monitoring tag is not activated.' % (node['name'], node['id']))
                else:
                    self.logger.debug('Different structure found, skipping...')


        except Exception:
            self.logger.error(traceback.format_exc())
            self.logger.error('Callback failed.')
            return None

    def process(self):
        self.logger.debug('Starting to process the CloudStack Event Queue...')
        self.channel.basic_consume(self.callback, queue=self.queue, no_ack=True)
        self.channel.start_consuming()

    def get_monitoring_by_id(self, id_):
        if not isinstance(id_, basestring) or not id_:
            return None
        vm = self.get_cached_vm(id_)
        if vm:
            return self.get_monitoring_tag(vm)
        else:
            return 0

    # @get_cached(cache=self.cache, owner=self.owner)
    def get_vm(self, id_):
        """Gets a single VM from CS API by its id. Returns a dict"""
        vm = self.cs_api.listVirtualMachines(id=id_).get('virtualmachine', [])
        if vm and isinstance(vm, list) and isinstance(vm[0], dict):
            vm[0]['role'] = 'VIRTUAL_MACHINE'
            return vm[0]
        else:
            return None

    def get_cached_vm(self, id_):
        """Gets objs from the Cache or proceeds with the API Call"""
        if not isinstance(id_, basestring) or not id_:
            raise TypeError('Argument id_ must be a non empty str.')
        cache = self.cache
        owner = self.owner
        if cache.ping():
            try:
                self.logger.debug('Will try retrieve a cached object.')
                return cache.get_artifact(owner=owner, session='vms', id_=id_)
            except (CacheError, CacheMiss) as e:
                self.logger.error('%s. Will do an API call.', e)
        else:
            self.logger.debug('Cache not available. Will do an API call.')
        return self.get_vm(id_)

    def assign_tag_zbx(self, owner, hostname, key, value, delete_tag=False):
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
                cs_vars = {}
                if tags.get('zabbix_api'):
                    vm = self.get_cached_vm(hostname)
                    if vm:
                        cs_vars = self.get_cs_vars(vm)
                self.update_zbx_from_tag(owner, host, tags, aggregator, cs_vars=cs_vars)
                self.queue_updates += 1
            # tag removed and existing host
            else:
                # monitoring tag removed and no monitoring tag left
                if int(tags.get('monitoring', 0)) and not self.get_monitoring_by_id(hostname):
                    self.delete_zbx_host_simple(owner, host)
                    self.queue_deletes += 1
                else:
                    self.update_zbx_from_tag(owner, host, tags, aggregator, delete_tag=True)
                    self.queue_updates += 1
        else:
            # Non existing host and monitoring tag created
            if (int(tags.get('monitoring', 0)) and not delete_tag) or self.get_monitoring_by_id(hostname):
                vm = self.get_cached_vm(hostname)
                if vm:
                    self.logger.debug('Host %s will be created in Zabbix, its monitoring tag is activated.' % hostname)
                    self.create_zabbix_host(owner, hostname, vm)
                    self.queue_creates += 1
                else:
                    self.logger.debug('VM %s not found. Will not be created' % hostname)
            else:
                self.logger.debug('Node %s will not be checked.' % hostname)
