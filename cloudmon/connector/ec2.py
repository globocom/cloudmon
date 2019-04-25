# -*- coding: utf-8 -*-

import traceback
import json
import threading
import time

from datetime import datetime

import boto3
from botocore.config import Config as AWSConfig

from cloudmon.connector.zabbix import ZabbixAPIException
from cloudmon.connector.base import BaseConnector
from cloudmon.connector.ec2_queue import EC2Queue

from cloudmon.utils.log import logging


def get_last_exec_ec2():
    return 0

class EC2Connector(BaseConnector):

    EC2_PARAMS = [
        'id',
        # 'cpu_options',
        'hypervisor',
        # 'image_id',
        'instance_type',
        'key_name',
        # 'launch_time',
        # 'monitoring',
        # 'network_interfaces_attribute',
        'placement',
        'private_dns_name',
        'private_ip_address',
        # 'public_dns_name',
        # 'public_ip_address',
        # 'security_groups',
        'state',
        # 'subnet_id',
        'tags',
        # 'vpc_id',
]
    EXTRA_PARAMS = {}

    def __init__(self, config):
        self.type = 'ec2'
        super(EC2Connector, self).__init__(config)
        self.logger = logging.getLogger("cloudmon." + self.type)
        self.monitored = self.config.get('monitored_instances', {})
        self.logger.info(
            "The following types of instance will be monitored as: %s",
            self.monitored
        )
        # self.logger.info(
        #     "Timeout for CloudStack HTTP(s) requests is %ss",
        #     self.config['cloudstack']['timeout']
        # )
        # ssl_config = self.config['ssl']
        # if ssl_config['verify_cloudstack'] and ssl_config['ca_bundle']:
        #     self.verify_cs = ssl_config['ca_bundle']
        #     self.logger.info(
        #         'All HTTPS requests to CloudStack are gonna be '
        #         'verified! Cert Bundle: %s',
        #         self.verify_cs
        #     )
        # elif ssl_config['verify_cloudstack']:
        #     self.verify_cs = True
        #     self.logger.info(
        #         'All HTTPS requests to CloudStack are gonna be verified!'
        #     )
        # else:
        #     self.verify_cs = False
        #     self.logger.warning(
        #         'According to your configuration, all HTTPS requests to '
        #         'CloudStack are not gonna be verified!'
        #     )

    def __call__(self, hostname, params):
        try:
            self.logger.debug('Called with: %s, %s', hostname, params)
            result = self.run_command(hostname, params)
            if result is not None and result["result"]:
                self.logger.info(
                    'Thread execution was finished with success!'
                )
            else:
                self.logger.error(
                    'Thread execution failed. The thread was finished.'
                )
        except Exception:
            self.logger.error(traceback.format_exc())

    def run_command(self, hostname, params):
        command = params.get('command', 'api')
        ec2 = self.get_ec2_api(hostname)
        self.logger.debug('Command received: %s', command)
        if not ec2:
            self.logger.error('Failed to connect to EC2 API.')
            return {'result': False, 'message': 'Failed to connect to EC2 API'}

        if command == 'api':
            self.metrics['monitor'].start()
            result = self.monitor(hostname, ec2)
            metrics_monitor = self.metrics['monitor'].stop()
            self.zabbix_sender(hostname, "metrics.monitor", metrics_monitor)
            message = "Succeeded" if result is True else "Failed"
            self.zabbix_sender(hostname, "monitor.status", message)
            return {"result": result, "message": message}
        elif command == 'queue':
            url = self.get_user_macro(hostname, self.MACRO_QUEUE_URL)
            queue_name = self.get_user_macro(hostname, self.MACRO_QUEUE_QUEUE)
            exchange = self.get_user_macro(hostname, self.MACRO_QUEUE_EXCHANGE)
            if url and queue_name and exchange:
                params = {'url':url, 'queue':queue_name, 'exchange':exchange}
                queue = EC2Queue(hostname, params, self.config)
            else:
                self.logger.warning(
                    'Zabbix Macro Queue params (%s, %s, %s) not found in host '
                    '%s. Cant connect to the AWS EC2 Event Queue.'
                    % (
                        self.MACRO_QUEUE_URL, self.MACRO_QUEUE_QUEUE,
                        self.MACRO_QUEUE_EXCHANGE, hostname))
                return None
            try:
                queue.process()
            except Exception as e:
                self.logger.error('Failed to process AWS EC2 queue: %s', e)
                self.logger.error(traceback.format_exc())
                return None

        else:
            return {"result": False, "message": "Command %s not available" % command}

    def create_aws_session(self, key, secret, region):
        return boto3.Session(
            aws_access_key_id=key,
            aws_secret_access_key=secret,
            region_name=region
        )

    def get_ec2_api(self, hostname):
        host = self.get_zabbix_host(hostname)
        if not host:
            self.logger.warning('Zabbix host "%s" does not exist', hostname)
            return None
        if host['inventory'] and host['inventory'].get('type', '0') == self.type:
            owner_hostname = host['inventory']['tag']
        else:
            owner_hostname = hostname
        key = self.get_user_macro(owner_hostname, self.MACRO_KEY)
        secret = self.get_user_macro(owner_hostname, self.MACRO_SECRET)
        region = self.get_user_macro(owner_hostname, self.MACRO_REGION)

        if region and secret and key:
            session = self.create_aws_session(key, secret, region)
            ec2 = session.resource('ec2')
            self.logger.info('EC2 session was created!')
            return ec2
            # validate conn
            # try:
            #     ec2.something()
            #     self.logger.info('EC2 connection was successful!')
            #     return ec2
            # except Exception as e:
            #     self.logger.error('CloudStack API Login failed: %s', e)
            #     return False
        else:
            self.logger.error(
                'Failed to get credentials from zabbix or macros not found.')
            return False

    def get_vms(self, ec2, owner):
        vms = []

        to_mon = self.monitored['virtual_machines']

        if to_mon == 'all':
            self.logger.info(
                'All hosts will be monitored despite its tags', self.mon_tags
            )
            search = ec2.instances.all()

        elif to_mon == 'tagged':
            self.logger.info(
                'Hosts with any of the following tags active %s will be '
                'monitored', self.mon_tags
            )
            search = ec2.instances.all()
            # filters = [{'Name': 'tag:{0}'.format(tag), 'Values': ['1']} for tag in self.mon_tags]
            # self.logger.info(filters)
            # search = ec2.instances.filter(Filters=filters)

        else:
            return vms

        for vm in search:
            vm_dict = {p: vm.__getattribute__(p) for p in self.EC2_PARAMS}
            vm_dict = self.organize_vm_dict(vm_dict)
            if (to_mon == 'tagged' and vm_dict['monitor_cloudmon']) or to_mon == 'all':
                vms.append(vm_dict)
        return vms

    def organize_vm_dict(self, vm_dict):
        if vm_dict.get('state'):
            vm_dict['state'] = vm_dict['state'].get('Name', 'NOT FOUND')

        vm_dict['monitor_cloudmon'] = 0
        tags = []
        if vm_dict.get('tags'):
            tags = [{'key': i['Key'], 'value': i['Value']} for i in vm_dict['tags']]
            for tag in tags:
                if tag['key'] == 'Name':
                    vm_dict['name'] = tag['value']
                if tag['key'] in self.mon_tags:
                    vm_dict['monitor_cloudmon'] = 1

        vm_dict['tags'] = tags


        if vm_dict.get('name'):
            vm_dict['name'] = vm_dict.get('name') + '_' + vm_dict['id']
        else:
            vm_dict['name'] = vm_dict['id']
        vm_dict['role'] = 'EC2_INSTANCE'
        return vm_dict

    def get_infra(self, ec2, owner):
        infra = {
            'vms': [],
            'vrouters': [],
            'sysvms': [],
            'projects': [],
            'not_collected_projs': []
        }

        if self.monitored['virtual_machines'] in ['tagged', 'all']:
            infra['vms'] = self.get_vms(ec2, owner)

        # if self.monitored['virtual_routers'] in ['all']:
        #     infra['vrouters'] = self.get_vrouters(ec2)

        # if self.monitored['system_vms'] in ['all']:
        #     infra['sysvms'] = self.get_sysvms(ec2)

        return infra

    def monitor(self, owner, ec2):
        monitor_operations = self.get_macros_split(owner, self.MACRO_MON_OPS)
        if not monitor_operations:
            monitor_operations = self.config['cloudmon']['monitor_operations']
        self.logger.info(
            'The api thread will do the following operations: %s',
            monitor_operations
        )

        try:
            self.metrics['cloudstack'].start()
            infra = self.get_infra(ec2, owner)

            if not infra['not_collected_projs']:
                self.zabbix_sender(owner, 'cloudmon.getvms', 'Succeeded')
            else:
                self.zabbix_sender(
                    owner, 'cloudmon.getvms',
                    'Couldn\'t get VMs from projects: {0}'.format(
                        infra['not_collected_projs'])
                )

            if self.cache:
                self.logger.info('Checking Cache...')
                if self.cache.store_infra(owner, infra):
                    self.logger.info('Infra stored in Cache with success!')
                else:
                    self.logger.error('Failed to store infra in Cache!')

            ec2_hosts = infra['vms'] + infra['sysvms'] + infra['vrouters']
            metrics_cloudstack = self.metrics['cloudstack'].stop()
            self.zabbix_sender(owner, "metrics.cloudstack", metrics_cloudstack)

            self.zabbix_sender(owner, "cloudmon.cloudstackConnection", "Succeeded")
        except Exception as e:
            self.zabbix_sender(owner, "cloudmon.cloudstackConnection", str(e))
            self.logger.error("Failed to connect to AWS: %s" % str(e))
            self.logger.error(traceback.format_exc())
            return False

        options = {
            'output': 'extend',
            'selectInventory': 'extend',
            'selectInterfaces': 'extend',
            'selectParentTemplates': 'extend',
            'searchInventory': {'tag': owner},
            # 'search': {'name': owner},
        }

        self.metrics['zabbixget'].start()
        zbx_hosts = self.zabbix_api.host.get(**options)
        metrics_zabbixget = self.metrics['zabbixget'].stop()
        self.zabbix_sender(owner, "metrics.zabbixget", metrics_zabbixget)

        self.metrics['zabbixloop'].start()

        # not_remove = [i['host'] for i in zbx_hosts if i.get('inventory', {}).get('contract_number', '') in infra['not_collected_projs']]
        not_remove = [i['host'] for i in zbx_hosts if i.get('inventory', {}).get('contact', '') in infra['not_collected_projs']]

        zbx_hosts = {i['host']: i for i in zbx_hosts if i.get('inventory', {}).get('tag', '') == owner}
        ec2_hosts = {i['id']: i for i in ec2_hosts}

        zbx_only = list(set(zbx_hosts.keys()) - set(ec2_hosts.keys()))
        aws_only = list(set(ec2_hosts.keys()) - set(zbx_hosts.keys()))
        in_aws_zbx = list(set(zbx_hosts).intersection(set(ec2_hosts)))

        zbx_only = list(set(zbx_only) - set(not_remove))

        # self.logger.info( '\n#zbx_only\n%s, \n#aws_only\n%s, \n#both\n%s', zbx_only, aws_only, in_aws_zbx)
        # self.logger.info( '%s, %s, %s', len(zbx_only), len(aws_only), len(in_aws_zbx))
        valid_states = self.STATES_ENABLED + self.STATES_DISABLED

        cre_ids = {}
        upd_ids = {}
        del_ids = {}

        # Create
        if 'create' in monitor_operations:
            for hostname in aws_only:
                state = ec2_hosts[hostname].get('state', 'NOT FOUND')
                name = ec2_hosts[hostname].get('name', hostname)
                if state in valid_states:
                    self.logger.debug(
                        '%s(%s) exists only in AWS. CloudMon will '
                        'attempt to create it in Zabbix',
                        name, hostname
                    )
                    cre_id = self.create_zabbix_host(
                        owner, hostname, ec2_hosts[hostname])
                    if cre_id:
                        cre_ids[cre_id] = [name, hostname]
                else:
                    self.logger.debug(
                        '%s(%s) exists only in AWS but has state %s. '
                        'CloudMon won\'t create it',
                        name, hostname, state
                    )
        else:
            self.logger.debug(
                'Create operations are not active for the api thread'
            )

        # Delete
        if 'delete' in monitor_operations:
            # Move to deleted hostgroup
            # Temporarily deleting perm all ec2
            if False:
            # if self.deleted_hosts_groupid:
                for hostname in zbx_only:
                    now = '_' + datetime.today().strftime(self.TIME_FORMAT) + '_'
                    name = zbx_hosts[hostname].get('name', hostname)
                    zbx_name = self.adjust_string_length(now + name, '', self.VISIBLE_NAME_MAX_LENGTH)
                    inventory.update = {
                        "type": self.type,
                        "tag": '_DELETED_' + owner,
                    }
                    # inventory.update(self.extra_inventory_data(node))
                    try:
                        self.zabbix_api.host.update(**{
                            'hostid': zbx_hosts[hostname]['hostid'],
                            'host':  now + hostname,
                            'name': zbx_name,
                            'groups': self.deleted_hosts_groupid,
                            'status': 1,
                            'inventory':inventory,
                        })
                        del_ids[zbx_hosts[hostname]['hostid']] = [name, hostname]
                        self.logger.debug(
                            'Host %s(%s, %s) was moved to the Deleted Hosts Group(%s)',
                            name,
                            zbx_hosts[hostname]['hostid'],
                            hostname,
                            self.deleted_hosts_groupid
                        )
                    except ZabbixAPIException as e:
                        self.logger.error(
                            'CloudMon attempt to move host %s(%s, %s) to '
                            'Deleted Hosts Group(%s) has failed: %s',
                            name,
                            zbx_hosts[hostname]['hostid'],
                            hostname,
                            self.deleted_hosts_groupid,
                            e
                        )
                if del_ids:
                    self.logger.info(
                        'Deleted hosts from Zabbix (moved to '
                        'Deleted Hosts Group(%s)): %s',
                        self.deleted_hosts_groupid, json.dumps(del_ids, indent=2)
                    )
            # Delete permanently
            else:
                del_ids = {zbx_hosts[i]['hostid']: [zbx_hosts[i].get('name', i), i] for i in zbx_only}
                if del_ids:
                    try:
                        self.zabbix_api.host.delete(*del_ids.keys())
                        self.logger.info(
                            'DELETED hosts from Zabbix: %s', json.dumps(del_ids, indent=2)
                        )
                    except ZabbixAPIException as e:
                        self.logger.error(
                            'CloudMon attempt to remove hosts the following '
                            'hosts has failed: %s\n%s', del_ids, e
                        )
        else:
            self.logger.debug(
                'Delete operations are not active for the api thread'
            )

        # Update
        if 'update' in monitor_operations:
            for hostname in in_aws_zbx:
                hostid = zbx_hosts[hostname]['hostid']
                name = zbx_hosts[hostname].get('name', hostname)
                state = ec2_hosts[hostname].get('state', 'NOT FOUND')

                self.logger.debug('#updating %s(%s, %s)',
                    name, hostid, hostname
                )

                result = self.update_zabbix_host(
                    owner, hostname, ec2_hosts[hostname], zbx_hosts[hostname])

                if result:
                    upd_ids[hostid] = [name, hostname]

                    created_time = self.get_creations(self.CREATIONS_FILE, hostname)
                    if created_time and zbx_hosts[hostname]['status'] == '0':
                        now = int(time.time())
                        if created_time > 0 and  (now - created_time > self.CREATION_INTERVAL):
                            if result:
                                proxy_addr = result[1]
                            else:
                                proxy_addr = self.prx_id_addresses.get(zbx_hosts[hostname]['proxy_hostid'], [self.zabbix_server, self.zabbix_port])

                            self.logger.debug("Sending zabbix_senders to %s. Host has longer creation than %ss" % (hostname, self.CREATION_INTERVAL))
                            if ec2_hosts[hostname].get('role') == "SYSTEM_VM":
                                self.zabbix_sender(hostname, "systemvm.state", ec2_hosts[hostname]['state'], proxy_addr[0], proxy_addr[1])
                                self.zabbix_sender(hostname, "systemvm.agentstate", ec2_hosts[hostname].get('agentstate', 'null'), proxy_addr[0], proxy_addr[1])
                            else:
                                self.zabbix_sender(hostname, "instance.state", ec2_hosts[hostname]['state'], proxy_addr[0], proxy_addr[1])


                        elif created_time > 0 and  (now - created_time <= self.CREATION_INTERVAL):
                            self.logger.debug("Host %s has a creation interval < %s and will yet not receive zabbix senders" % (hostname, self.CREATION_INTERVAL))
                        else:
                            output = self.log_creations(self.CREATIONS_FILE, hostname)
                            if output:
                                self.logger.debug("Entry \"%s = %s\" was added/edited to creations file \"%s\"" % (output[0], output[1], self.CREATIONS_FILE))
                            else:
                                self.logger.warning("Could not edit the creations file \"%s\"" % self.CREATIONS_FILE)
        else:
            self.logger.debug(
                'Update operations are not active for the api thread'
            )

        if cre_ids:
            self.logger.info('[EC2] CREATED hosts in Zabbix: %s', json.dumps(cre_ids, indent=2))
        if upd_ids:
            self.logger.info('[EC2] UPDATED hosts in Zabbix: %s', json.dumps(upd_ids, indent=2))

        len_cre, len_upd, len_del = len(cre_ids), len(upd_ids), len(del_ids)
        self.logger.info(
            '[EC2] In total CloudMon created %s, updated %s and deleted %s '
            'hosts from Zabbix', len_cre, len_upd, len_del
        )
        metrics_zabbixloop = self.metrics['zabbixloop'].stop()
        self.zabbix_sender(owner, "metrics.zabbixloop", metrics_zabbixloop)
        self.zabbix_sender(owner, "metrics.apicreates", len_cre)
        self.zabbix_sender(owner, "metrics.apiupdates", len_upd)
        self.zabbix_sender(owner, "metrics.apideletes", len_del)

        return True
