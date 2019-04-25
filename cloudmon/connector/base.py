# -*- coding: utf-8 -*-

import os
import re
import json
import traceback
import random
import string

from time import time
from datetime import datetime
from unidecode import unidecode

from configobj import ConfigObj
from cloudmon.connector.zabbix import ZabbixAPICM, ZabbixAPIException

from cloudmon.connector.metrics import Metrics
from cloudmon.connector.proxy_queue import ProxyQueue

from cloudmon.utils.parse import to_bool
from cloudmon.utils.parse import filter_blacklist
from cloudmon.utils.parse import list_monitoring_tags
from cloudmon.utils.config import SCHEMA
from cloudmon.utils.config import CustomValidator
from cloudmon.utils.log import logging
from cloudmon.connector.cache import Cache

from cloudmon.connector.errors import CacheError, CacheMiss


class BaseConnector(object):

    STATES_ENABLED = [
        'Running',
        'running'
    ]
    STATES_DISABLED = [
        'Starting',
        'Stopping',
        'stopping',
        'Stopped',
        'stopped',
        'Migrating',
        'Error',
        'Unknown',
        'Shutdowned',
        'shutting-down',
        'pending'
    ]
    STATES_DELETED = [
        'Destroyed',
        'Expunging',
        'terminated'
    ]

    MACRO_URL = '{$URL}'
    MACRO_KEY = '{$KEY}'
    MACRO_SECRET = '{$SECRET}'
    MACRO_REGION = '{$REGION}'
    MACRO_MON_OPS = '{$MONITOR_OPERATIONS}'
    MACRO_GROUPS = '{$VM_GROUPS}'
    MACRO_ROUTER_GROUPS = '{$ROUTER_GROUPS}'
    MACRO_SYSTEM_VM_GROUPS = '{$SYSTEM_VM_GROUPS}'
    MACRO_REQUIRED_TEMPLATES = '{$REQUIRED_TEMPLATES}'
    MACRO_TEMPLATES = '{$VM_TEMPLATES}'
    MACRO_ROUTER_TEMPLATES = '{$ROUTER_TEMPLATES}'
    MACRO_SYSTEM_VM_TEMPLATES = '{$SYSTEM_VM_TEMPLATES}'
    MACRO_TEMPLATES_LINUX = '{$VM_TEMPLATES_LINUX}'
    MACRO_TEMPLATES_WINDOWS = '{$VM_TEMPLATES_WINDOWS}'
    MACRO_AGGREGATE_TEMPLATE = '{$AGGREGATE_TEMPLATE}'

    MACRO_EXTRA_STR = {
        'templates': '{$EXTRA_TEMPLATES_STR}',
        'hostgroups': '{$EXTRA_GROUPS_STR}',
        'macros': '{$EXTRA_MACROS_STR}',
        'classes': '{$EXTRA_CLASS_STR}',
        'methods': '{$EXTRA_METHOD_STR}'
    }
    MACRO_EXTRA_STR['hostgroups_2'] = '{$EXTRA_GROUPS_2_STR}'

    MACRO_USERGROUPS = "{$USERGROUPS}"
    MACRO_QUEUE_URL = "{$QUEUE_URL}"
    MACRO_QUEUE_QUEUE = "{$QUEUE_QUEUE}"
    MACRO_QUEUE_EXCHANGE = "{$QUEUE_EXCHANGE}"
    NOT_EXIST_HOST_NAME_PREFIX = "_DELETED_"
    VISIBLE_NAME_MAX_LENGTH = 64
    CREATIONS_FILE = '/tmp/.creations.cloudmon'
    CREATION_INTERVAL = 1200
    TIMEOUT = 500
    TIME_FORMAT = '%y%m%d%H%M%f'
    STR_FILLER = 3

    ZABBIX_EXPIRES = 10800  # 3h

    def __init__(self, config):
        self.metrics = {
            'zabbixget': Metrics(),
            'zabbixloop': Metrics(),
            'cloudstack': Metrics(),
            'monitor': Metrics()
        }
        self.type = "cloudstack"
        self.config = config
        self.mon_tags = list_monitoring_tags(config['cloudstack_tags'])
        self.logger = logging.getLogger("cloudmon.base")
        if self.config['logging']['zabbix_api_log_file']:
            self.logger_tags = logging.getLogger('tags')
        else:
            self.logger_tags = logging.getLogger("cloudmon.base")

        if config['cloudmon']['use_cache']:
            try:
                self.cache = Cache(save='')
                self.logger.info('Redis Cache will be used.')
            except CacheError as e:
                self.cache = None
                self.logger.error('Redis Cache not available: %s', e)
        else:
            self.cache = None
            self.logger.info('Redis Cache won\'t be used.')

        self.zabbix_server = config["zabbix"].get('zabbix_server', 'localhost')
        self.zabbix_port = config["zabbix"].get('zabbix_port', '10051')
        self.zabbix_sender_path = config["zabbix"].get('zabbix_sender', '/usr/bin/zabbix_sender')
        frontend_url = config["zabbix"].get('frontend_url', "http://%s/zabbix" % self.zabbix_server)
        zabbix_user = config["zabbix"].get('zabbix_user', 'Admin')
        zabbix_password = config["zabbix"].get('zabbix_password', 'zabbix')

        self.zabbix_api = ZabbixAPICM(frontend_url, timeout=self.TIMEOUT)
        ssl_config = self.config['ssl']
        if ssl_config['verify_zabbix'] and ssl_config['ca_bundle']:
            self.zabbix_api.session.verify = ssl_config['ca_bundle']
            self.logger.info(
                'All HTTPS requests to Zabbix are gonna be verified! '
                'Cert Bundle: %s',
                self.zabbix_api.session.verify
            )
        elif ssl_config['verify_zabbix']:
            self.zabbix_api.session.verify = True
            self.logger.info(
                'All HTTPS requests to Zabbix are gonna be verified!'
            )
        else:
            self.zabbix_api.session.verify = False
            self.logger.warning(
                'According to your configuration, all HTTPS requests to Zabbix'
                ' are not gonna be verified!'
            )

        self.prx_queue = False
        self.validator = CustomValidator()
        try:
            self.zabbix_api.login(zabbix_user, zabbix_password)
            self.logger.info('Zabbix API Login was successful!')
        except Exception as e:
            self.logger.error('Zabbix API Login failed: %s', e)
            raise

        if config["zabbix"].get('deleted_hosts_group', False):
            self.deleted_hosts_groupid = self.zabbix_api.hostgroup.get(**{"filter": {"name": self.config["zabbix"]['deleted_hosts_group']}})
        else:
            self.deleted_hosts_groupid = False

        if config["zabbix"].get('proxies', False):
            prx_ids = {}
            prx_id_addresses = {}
            for prx, prx_conf in config["zabbix"]['proxies'].iteritems():
                if isinstance(prx_conf, (basestring, int, float)):
                    weight = prx_conf
                    address = None
                elif isinstance(prx_conf, dict) and prx_conf.get('weight') and prx_conf.get('address'):
                    weight = prx_conf['weight']
                    address = prx_conf['address']
                    self.logger.warning("Zabbix senders will also be done by proxy %s(%s)" % (prx, address))
                else:
                    raise TypeError('Wrong type with %s', str(prx_conf))
                prx_id = self.proxy_to_id(prx)
                weight = int(weight)

                if prx_id >= 0:
                    self.logger.info("Weight %s of the hosts will be monitored  by Proxy %s(%s)" % (weight, prx, prx_id))
                    prx_ids[prx_id] = weight
                    prx_id_addresses[prx_id] = address.split(':')
                else:
                    if prx_ids.get(prx_id, False):
                        prx_ids[0] += weight
                    else:
                        prx_ids[0] = weight
                        prx_id_addresses[prx_id] = address.split(':')

                    if prx_id == 0:
                        self.logger.info(
                            "Weight %s of the hosts will be monitored by the Zabbix Server" % (weight))

                    else:
                        self.logger.warning("Proxy %s not found. Weight %s of the hosts will be monitored by the Zabbix Server" % (prx, weight))


            self.prx_queue = ProxyQueue(prx_ids)
            self.prx_id_addresses = prx_id_addresses
            self.logger.info("Proxy id adresses: %s" % str(self.prx_id_addresses))

        else:
            self.zabbix_proxyid = 0
            self.prx_id_addresses = {0:[self.zabbix_server, self.zabbix_port]}
            self.logger.info("Hosts will be monitored by the Zabbix Server")

        if int(config["zabbix"].get('update_proxy', 0)):
            self.logger.info("Hosts that already exist in cloudmon might change proxies in order to create the requested proxy structure. (update_proxy = 1)")
        else:
            self.logger.info("Hosts that already exist in cloudmon won't change proxies. (update_proxy = 0)")

    def __call__(self, hostname, params):
        raise NotImplementedError("this connector is not implemented")


    def proxy_to_id(self, proxy_name):
        if proxy_name == "Zabbix Server":
            return 0
        else:
            proxyid = self.zabbix_api.proxy.get(**{'filter':{'host': proxy_name}})
            if proxyid:
                return int(proxyid[0]['proxyid'])
            else:
                return -1

    def zabbix_sender(self, zabbix_hostname, key, value, server=None, port=None ):
        if value is None:
            value = ""
        elif not isinstance(value, str):
            value = json.dumps(value)
        if server == None:
            server = self.zabbix_server
        if port == None:
            port = self.zabbix_port
        args = (self.zabbix_sender_path, server, port, zabbix_hostname, key, value)
        cmd = "%s -z %s -p %s -s %s -k %s -o %s > /dev/null 2>&1" % self.escape_shell_args(args)
        return_code = os.system(cmd)
        if return_code != 0:
            self.logger.warning('Zabbix Sender Failed [%s, %s, %s, %s, %s]' % (zabbix_hostname, key, value, server, port))
            self.logger.warning("Failed to run zabbix_sender. Params => %s" % str(args))
        else:
            self.logger.info('Zabbix Sender [%s, %s, %s, %s, %s] was successful' % (zabbix_hostname, key, value, server, port))


    # TODO: use subprocess
    def escape_shell_args(self, args):
        if not isinstance(args, tuple) and not isinstance(args, list):
            args = [args]
        return tuple(["\\'".join("'" + p + "'" for p in str(arg).split("'")) for arg in args])

    def addresses_to_interfaces(self, addresses, interface_types=[1, 2], main=True):
        ports = {1: 10050, 2: 161, 3: 623, 4: 12345}  # 1: Zabbix Agent, 2: SNMP, 3: IPMI, 4: JMX
        interfaces = []
        if not isinstance(addresses, list):
            addresses = [addresses]
        for addr in addresses:
            if (not isinstance(addr, basestring)) or addr == "":
                continue
            if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', addr):
                for type in interface_types:
                    interfaces.append({"type": type, "useip": 1, "ip": addr, "dns": "", "port": ports[type], "main": 0})
            else:
                for type in interface_types:
                    interfaces.append({"type": type, "useip": 0, "ip": "", "dns": addr, "port": ports[type], "main": 0})
        if interfaces:
            if main:
                for type in interface_types:
                    type_interfaces = [interface for interface in interfaces if interface["type"] == type]
                    main_interfaces = [interface for interface in type_interfaces if interface["useip"] == 0]
                    if main_interfaces:
                        main_interfaces[0]["main"] = 1
                    elif type_interfaces:
                        type_interfaces[0]["main"] = 1
            return interfaces
        else:
            for type in interface_types:
                interfaces.append({"type": type, "useip": 0, "ip": "", "dns": "dummy-interface.invalid", "port": ports[type], "main": 1 if main else 0})
            return interfaces

    def interfaces_to_addresses(self, interfaces):
        addresses = []
        if not isinstance(interfaces, list):
            interfaces = [interfaces]
        for interface in interfaces:
            if (not isinstance(interface, dict)) or "useip" not in interface:
                continue
            addr = interface["ip"] if int(interface["useip"]) == 1 else interface["dns"]
            addresses.append(addr)
        return addresses

    def get_zabbix_host(self, hostname):
        hosts = self.zabbix_api.host.get(**{"filter": {"host": hostname},"output": "extend","selectInterfaces": "extend","selectMacros": "extend","selectGroups": "extend","selectInventory": "extend",})
        if hosts:
            return hosts[0]
        else:
            return None

    def get_zabbix_interfaces(self, hostname, interface_type=None, main=False):
        hosts = self.zabbix_api.host.get(**{
            "filter": {"host": hostname},
            "selectInterfaces": "extend",
        })
        if hosts:
            interfaces = hosts[0]["interfaces"]
            if isinstance(interfaces, dict):
                interfaces = interfaces.values()
            if interface_type:
                interfaces = [interface for interface in interfaces if int(interface["type"]) == interface_type]
            if main:
                interfaces = [interface for interface in interfaces if int(interface["main"]) == 1]
            return interfaces
        else:
            return []

    def get_user_macro(self, hostname, key):
        if not key:
            return ''
        if hostname:
            hosts = self.zabbix_api.host.get(**{"filter": {"host": hostname}, "selectMacros": "extend", "selectParentTemplates": ["templateid"]})
            if hosts:
                # search host macro
                if "macros" in hosts[0]:
                    macros = hosts[0]["macros"]
                    if isinstance(macros, dict):
                        macros = macros.values()
                    macros = [macro for macro in macros if macro["macro"] == key]
                    if macros:
                        return macros[0]["value"]
                # search template macro
                template_ids = [template["templateid"] for template in hosts[0]["parentTemplates"]]
                templates = self.zabbix_api.template.get(**{"templateids": template_ids, "selectMacros": "extend"})
                for template in templates:
                    if "macros" in template:
                        macros = [macro for macro in template["macros"] if macro["macro"] == key]
                        if macros:
                            return macros[0]["value"]
        global_macros = self.zabbix_api.usermacro.get(**{"globalmacro": True, "filter": {"macro": key}})
        if global_macros:
            return global_macros[0]["value"]
        else:
            macros_in_file = self.config.get('host_macros')
            return macros_in_file.get(key, '')


    def get_group_ids(self, owner_hostname, key=None):
        group_names = self.get_macros_split(owner_hostname, key)
        return self.group_ids_from_names(owner_hostname, group_names)

    def get_macros_split(self, owner_hostname, key=None):
        if not key:
            key = self.MACRO_GROUPS
        macro_value = self.get_user_macro(owner_hostname, key)
        names = [name.strip() for name in macro_value.split(',')] if macro_value else []
        return names

    def group_ids_from_names(self, owner_hostname, group_names, is_project=False):
        groups = []
        for group_name in group_names:
            grp = self.zabbix_api.hostgroup.get(**{"filter": {"name": group_name}})
            if grp:
                groups.append({"groupid": grp[0]["groupid"]})
            else:
                self.logger.info("Group '%s' does not exist. Creating group..." % group_name)
                try:
                    response = self.zabbix_api.hostgroup.create(**{"name": group_name})
                    self.permission_to_usergroups(owner_hostname, response["groupids"][0])
                    groups.append({"groupid": response["groupids"][0]})
                    self.logger.info("Group '%s'(%s) created!" % (group_name, response["groupids"][0]))
                    if is_project:
                        self.create_aggregate_host(owner_hostname, group_name, response["groupids"][0], )
                except ZabbixAPIException as e:
                    self.logger.warning("Cant create group: %s" % str(e))
        return groups

    def get_template_ids(self, owner_hostname, key=None):
        template_names = self.get_macros_split(owner_hostname, key)
        return self.template_ids_from_names(template_names)

    def template_ids_from_names(self, template_names):
        templates = []
        for template_name in template_names:
            tmpl = self.zabbix_api.template.get(**{"filter": {"host": template_name}})
            if tmpl:
                templates.append({"templateid": tmpl[0]["templateid"]})
            else:
                self.logger.warning("Template '%s' does not exist" % template_name)
        return templates

    def get_user_template_ids(self, owner_hostname, node):
        templates = self.get_template_ids(owner_hostname, self.MACRO_TEMPLATES)
        if "platform" not in node.extra:
            self.logger.warning("Unknown platform: %s" % node.id)
            return templates
        else:
            if node.extra["platform"] is not None and node.extra["platform"].lower().find("windows") != -1:
                key = self.MACRO_TEMPLATES_WINDOWS
            else:
                key = self.MACRO_TEMPLATES_LINUX
            return templates + self.get_template_ids(owner_hostname, key)

    def permission_to_usergroups(self, owner_hostname, grp_id):
        usergroups_names = self.get_macros_split(owner_hostname, self.MACRO_USERGROUPS)
        usergroups_ids = []
        for name in usergroups_names:
            usrgrp = self.zabbix_api.usergroup.get(**{'search': {'name': name}, 'output': 'usrgrpid'})
            if usrgrp:
                usergroups_ids.append(usrgrp[0]['usrgrpid'])
                self.logger.debug("Usergroup %s has id %s" % (name, usrgrp[0]['usrgrpid']))
            else:
                self.logger.warning("That wasn't found an id for the Usergroup %s" % name)

        if usergroups_ids:
            try:
                permission = self.zabbix_api.usergroup.massadd(**{
                    "usrgrpids": usergroups_ids,
                    "rights": {"permission": 3, "id": grp_id}
                })
                self.logger.debug("Usergroups %s received permission to hostgroup %s" % (usergroups_ids, grp_id))
                return True
            except ZabbixAPIException as e:
                self.logger.warning("Failed to add permission: %s" % str(e))
                return False
        else:
            self.logger.debug("No usergroups will receive permission to hostgroup %s" % grp_id)
            return False

    def get_assigned_template_ids(self, host):
        templates = []
        for tmpl in host['parentTemplates']:
            templates.append({"templateid": tmpl["templateid"]})
        return templates

    def adjust_string_length(self, base_string, suffix, max_length):
        fill = self.random_filler(self.STR_FILLER)
        if len(suffix) == 0:
            if len(base_string) > max_length:
                return base_string[0:max_length - (self.STR_FILLER+1)] + '_' + fill
            else:
                return base_string
        else:
            if len(base_string) + len(suffix) > max_length:
                if max_length < len(suffix):
                    return fill + '_' + suffix[len(suffix) - max_length + (self.STR_FILLER+1):]
                return base_string[0:max_length - len(suffix) - (self.STR_FILLER+2)] + '_'+ fill +'_' + suffix
            else:
                return base_string + "_" + suffix

    def create_aggregate_host(self, owner_hostname, group_name, group_id):
        response = self.zabbix_api.host.create(**{
            "host": "Aggregate_" + group_name,
            "interfaces": self.addresses_to_interfaces("127.0.0.1"),
            "groups": [{"groupid": group_id}],
            "templates": self.get_template_ids(owner_hostname, self.MACRO_AGGREGATE_TEMPLATE),
            "proxy_hostid": self.prx_queue.get_next() if self.prx_queue else self.zabbix_proxyid,
            "macros": [{"macro":"{$HOSTGROUP}", "value": group_name}],
        })

    def log_creations(self, file_creations, hostname):
        if re.match('^(.+\-){4}.+$', hostname) or re.match('^\w\-.+$', hostname):
            now = str(int(time()))
            try:
                creations = ConfigObj(file_creations)
                creations[hostname] = now
                creations.write()
                return [hostname, now]
            except IOError as e:
                self.logger.warning(
                    "Couldnt open the file \"%s\" for adding hostname \"%s\". "
                    "Error: %s",
                    file_creations, hostname, e
                )
                return False
        else:
            self.logger.warning("Hostname \"%s\ has an unexpected format and could not be logged in creations file \"%s\" " % (hostname, file_creations))
            return False
    def get_creations(self, file_creations, hostname):
        try:
            creations = ConfigObj(file_creations)
        except IOError, e:
            self.logger.warning("Couldnt open the file \"%s\" for reading. Error: %s" % (file_creations,e))
            return False
        created_time = creations.get(hostname, False)
        if created_time:
            return int(created_time)
        else:
            self.logger.debug("Couldnt find the time when \"%s\" was created" % hostname)
            return -1

    def process_tags(self, tag_list, hostname, owner):
        all_tags = {
            'monitoring': 0,
            'hostgroups': [],
            'templates': [],
            'macros': [],
            'zabbix_api': []
        }
        all_tags['hostgroups_2'] = []
        priority = {
            'monitoring': None,
            'macros': []
        }

        for tag in tag_list:
            (tag_valid, aggr) = self.validate_tag(tag['key'], tag['value'], owner)
            for k, v in tag_valid.iteritems():
                # not custom, has priority over customs
                if not aggr and (k == 'monitoring' or k == 'macros'):
                    priority[k] = v
                elif k == 'monitoring' and not int(all_tags.get(k, 0)):
                    all_tags[k] = v
                elif k in ['hostgroups', 'templates', 'macros', 'zabbix_api']:
                    all_tags[k].extend(v)
                elif k == 'hostgroups_2':
                    all_tags[k].extend(v)

        for k, v in all_tags.iteritems():
            if k == 'monitoring' and priority.get('monitoring'):
                all_tags['monitoring'] = priority['monitoring']
            elif k == 'macros':
                all_tags[k].extend(priority['macros'])
                all_tags[k] = self.unique_listofdict(all_tags[k], 'macro')
            elif k == 'hostgroups':
                hostgroups = list(set(v))
                all_tags[k] = self.group_ids_from_names(owner, hostgroups)
            elif k == 'hostgroups_2':
                hostgroups = list(set(v))
                all_tags[k] = self.group_ids_from_names(owner, hostgroups)
            elif k == 'templates':
                templates = list(set(v))
                all_tags[k] = self.template_ids_from_names(templates)

            if all_tags[k]:
                self.logger.debug(
                    "%s parameters: %s found in host %s configuration."
                    % (k, all_tags[k], hostname)
                )

        return all_tags

    def cs_status_to_zbx(self, visible_name, name, state):
        if state in self.STATES_ENABLED:
            self.logger.debug("Zabbix host \"%s\" will have ENABLED STATUS because its Cloudstack node \"%s\" has status \"%s\"" % (visible_name, name, state))
            return 0
        elif state in self.STATES_DISABLED:
            self.logger.debug("Zabbix host \"%s\" will have DISABLED STATUS because its Cloudstack node \"%s\" has status \"%s\"" % (visible_name, name, state))
        elif state in self.STATES_DELETED:
            self.logger.debug("Zabbix host \"%s\" will soon be deleted because its Cloudstack node \"%s\" has status \"%s\"" % (visible_name, name, state))
        else:
            self.logger.debug("Zabbix host \"%s\" will have DISABLED STATUS because its Cloudstack node \"%s\" has an unkown status" % (visible_name, name))
        return 1

    def update_status_zbx_from_cs(self, hostname, state):
        host = self.zabbix_hostget(hostname, ['hostid', 'name'])
        if not host:
            self.logger.debug("Host %s doesn't exist in Zabbix, its status can't be changed" % hostname)
            return None

        try:
            status = self.cs_status_to_zbx(host['name'], hostname, state)
            self.zabbix_api.host.update(**{'hostid': host['hostid'], 'status': status})
            self.logger.debug("Status of host %s(%s)(%s) updated in Zabbix!" % (host['name'], hostname, host['hostid']))
        except Exception:
            self.logger.error("Failed to update status in Zabbix")
            self.logger.error(traceback.format_exc())
            return None

    def update_zbx_from_tag(self, owner, host, tags, aggregator=None, delete_tag=False, cs_vars={}):
        if not delete_tag:
            self.logger.debug("[U] Simple UPDATE for Zabbix host %s(%s, %s) CREATING tag infos: %s %s" % (host.get('name', ''), host['host'], host['hostid'], aggregator, tags))
        else:
            self.logger.debug("[U] Simple UPDATE for Zabbix host %s(%s, %s) REMOVING tag infos: %s %s" % (host.get('name', ''), host['host'], host['hostid'], aggregator, tags))

        try:
            host['templates'] = host.pop('parentTemplates', [])

            templates = self.template_ids_from_names(tags.get('templates',[]))
            groups = self.group_ids_from_names(owner, tags.get('hostgroups',[]))

            groups_2 = self.group_ids_from_names(owner, tags.get('hostgroups_2',[]))
            groups.extend(groups_2)

            macros = tags.get('macros',[])

            if not delete_tag:
                host['templates'].extend(templates)
                host['templates'] = self.unique_listofdict(
                    host['templates'], 'templateid')

                host['groups'].extend(groups)
                host['groups'] = self.unique_listofdict(
                    host['groups'], 'groupid')

                host['macros'].extend(macros)
                host['macros'] = self.unique_listofdict(
                    host['macros'], 'macro')

                if tags.get('zabbix_api', []):
                    self.api_call_zabbix(tags['zabbix_api'], cs_vars)
            else:
                host['templates'] = self.subtract_listofdict(
                    host['templates'], templates, 'templateid')

                host['groups'] = self.subtract_listofdict(
                    host['groups'], groups, 'groupid')

                host['macros'] = self.subtract_listofdict(
                    host['macros'], macros, 'macro')

            self.zabbix_api.host.update(**host)
            self.logger.info("Update for %s was successful!" % host.get('name', host['hostid']))
            return True
        except ZabbixAPIException as e:
            self.logger.error("Failed to update zabbix host: %s" % str(e))
            return False

    def unique_listofdict(self, list1, index):
        """Returns list1 without duplicates (elements with same index,
        keeps only one) Format of lists => list of dicts: [{'index':1}]
        self.unique_listofdict([{'a':1}, {'a':1}, {'a':3}], 'a')
        returns [{'a':2}, {'a':3}]"""
        return {i[index]: i for i in list1}.values()

    def subtract_listofdict(self, list1, list2, index):
        """Returns list1 without elements that matches indexes
        in list2. Format of lists => list of dicts: [{'index':1}]
        self.subtract_listofdict(
            [{'a':1}, {'a':2}],
            [{'a':1}], 'a') returns [{'a':2}]"""

        dict1 = {i[index]: i for i in list1}
        dict2 = {i[index]: i for i in list2}
        for i in dict2.iterkeys():
            dict1.pop(i, None)
        return dict1.values()

    def validate_tag(self, tag_k, tag_v, owner):
        tags = self.config.get('cloudstack_tags')
        for kind, values in tags.iteritems():
            if kind == 'shortcuts':
                for custom_name, custom_values in values.iteritems():
                    if tag_k == custom_name:
                        self.logger.debug(
                            'Custom tag {%s:%s} validated!' % (tag_k, tag_v))
                        if to_bool(tag_v):
                            self.logger.debug('Values parsed and validated')
                            self.logger.debug(custom_values)
                            return (custom_values, custom_name)
                        else:
                            return ({}, custom_name)
            else:
                if tag_k == values:
                    self.logger.debug(
                        'Regular tag {%s:%s} found!' % (tag_k, tag_v))
                    if not ((kind == 'monitoring' and to_bool(tag_v)) or (kind != 'monitoring' and tag_v)):
                        break
                    return self.prepare_values_from_tags(owner, kind, tag_v )
        return ({}, None)


    def prepare_values_from_tags(self, owner, kind, tag_v):
        tags_schema = SCHEMA['cloudstack_tags']['schema']['shortcuts']['valueschema']['schema']
        if self.validator.validate({kind:tag_v}, tags_schema):
            parsed = self.validator.document
            blacklists = self.config['blacklisted']

            if kind == 'monitoring':
                pass

            elif kind == 'templates' or kind == 'hostgroups':
                ini_str = self.get_user_macro(owner, self.MACRO_EXTRA_STR.get(kind))
                concat = [ini_str.strip() + i for i in parsed[kind]]
                (filtered, blacklisted) = filter_blacklist(
                    concat,
                    blacklists[kind]['names'],
                    blacklists[kind]['regexps'],
                    self.logger
                )
                self.validator.validate({kind:filtered}, tags_schema)

            elif kind == 'hostgroups_2':
                ini_str = self.get_user_macro(owner, self.MACRO_EXTRA_STR.get(kind))
                concat = [ini_str.strip() + i for i in parsed[kind]]
                (filtered, blacklisted) = filter_blacklist(
                    concat,
                    blacklists['hostgroups']['names'],
                    blacklists['hostgroups']['regexps'],
                    self.logger
                )
                self.validator.validate({kind:filtered}, tags_schema)

            elif kind == 'macros':
                ini_str = self.get_user_macro(owner, self.MACRO_EXTRA_STR.get(kind))
                for i in parsed[kind]:
                    i['macro'] = i['macro'][:2] + ini_str.strip() + i['macro'][2:]
                (filtered, blacklisted) = filter_blacklist(
                    [i['macro'] for i in parsed[kind]],
                    blacklists[kind]['names'],
                    blacklists[kind]['regexps'],
                    self.logger
                )
                cond = lambda x: x['macro'] not in blacklisted
                filtered = filter(cond, parsed[kind])
                self.validator.validate({kind:filtered}, tags_schema)

            elif kind == 'zabbix_api':
                ini_str_cls = self.get_user_macro(owner, self.MACRO_EXTRA_STR.get('classes'))
                ini_str_mtd = self.get_user_macro(owner, self.MACRO_EXTRA_STR.get('methods'))
                for i in parsed[kind]:
                    i['class'] = ini_str_cls.strip() + i['class']
                    i['method'] = ini_str_mtd.strip() + i['method']
                (fil_cls, bl_cls) = filter_blacklist(
                    [i['class'] for i in parsed[kind]],
                    blacklists['classes']['names'],
                    blacklists['classes']['regexps'],
                    self.logger
                )
                (fil_mtd, bl_mtd) = filter_blacklist(
                    [i['method'] for i in parsed[kind]],
                    blacklists['methods']['names'],
                    blacklists['methods']['regexps'],
                    self.logger
                )
                cond = lambda x: x['class'] not in bl_cls and x['method'] not in bl_mtd
                filtered = filter(cond, parsed[kind])
                self.validator.validate({kind:filtered}, tags_schema)

            self.logger.debug('Values filtered and concatenated')
            self.logger.debug('Values parsed and validated')
            self.logger.debug(self.validator.document)
            return(self.validator.document, None)
        else:
            # Improve output
            self.logger.debug('Parsing failed!')
            return ({}, None)



    def create_zabbix_host(self, owner_hostname, hostname, node):
        base_string = owner_hostname + "_" + node['name']
        visible_name = self.adjust_string_length(base_string, "", self.VISIBLE_NAME_MAX_LENGTH)

        ip = None
        if node.get('role') == 'EC2_INSTANCE':
            ip = node.get('private_ip_address', None)

        elif not node.get('role') == "SYSTEM_VM":
            for i in node['nic']:
               if i.get('isdefault'):
                    ip = i.get('ipaddress')
                    break
        else:
            ip = node.get('publicip', None)

        if not ip:
            self.logger.warning("Failed to create zabbix host %s (%s) - no valid ip assigned to host" % (hostname, visible_name))
            return False

        # create host
        response = None
        try:
            inventory = {
                "name": self.adjust_string_length(node['name'], "", self.VISIBLE_NAME_MAX_LENGTH),
                "type": self.type,
                "tag": owner_hostname,
            }
            inventory.update(self.extra_inventory_data(node))
            (macro_groups, macro_templates) = self.get_role_macro(node)
            tag_info = self.process_tags(node.get('tags', []), hostname, owner_hostname)

            templates = self.get_template_ids(owner_hostname, macro_templates) + tag_info['templates']
            if node.get('role') == "VIRTUAL_MACHINE":
                hostgroups = self.get_group_ids(owner_hostname, macro_groups)
                hostgroups += self.get_project_to_group(owner_hostname, node)
                hostgroups += tag_info['hostgroups']
                hostgroups += tag_info['hostgroups_2']
            else:
                hostgroups = self.get_group_ids(owner_hostname, macro_groups)
            # Remove Duplicates
            templates = self.unique_listofdict(templates, 'templateid')
            hostgroups = self.unique_listofdict(hostgroups, 'groupid')

            status = self.cs_status_to_zbx(visible_name, node['name'], node['state'])

            response = self.zabbix_api.host.create(**{
                "host": hostname,
                "name": visible_name,
                "interfaces": self.addresses_to_interfaces(ip),
                "groups": hostgroups,
                "templates": templates,
                "inventory": inventory,
                "proxy_hostid": self.prx_queue.get_next() if self.prx_queue else self.zabbix_proxyid,
                "macros": tag_info['macros'],
                "status": status
            })
            created_id = response['hostids'][0]
            self.logger.debug("[C] Zabbix host %s(%s, %s) was CREATED with success!" % (visible_name, hostname, created_id))
            output = self.log_creations(self.CREATIONS_FILE, hostname)
            if output:
                self.logger.debug("Entry \"%s = %s\" was added/edited to creations file \"%s\"" % (output[0], output[1], self.CREATIONS_FILE))
            else:
                self.logger.warning("Could not edit the creations file \"%s\"" % self.CREATIONS_FILE)
            return str(created_id)
        except ZabbixAPIException as e:
            self.logger.error(
                'FAILED TO CREATE host %s(%s) in Zabbix: %s',
                node['name'], hostname, e
            )
            return ''


    def update_zabbix_host(self, owner_hostname, hostname, node, host):
        base_string = owner_hostname + "_" + node['name']
        visible_name = self.adjust_string_length(base_string, "", self.VISIBLE_NAME_MAX_LENGTH)
        try:
            status = self.cs_status_to_zbx(visible_name, node['name'], node['state'])
            inventory = {
                "name": self.adjust_string_length(node['name'], "", self.VISIBLE_NAME_MAX_LENGTH),
                "type": self.type,
                "tag": owner_hostname,
            }
            inventory.update(self.extra_inventory_data(node))
            tag_info = self.process_tags(node.get('tags', []), hostname, owner_hostname)

            (macro_groups, macro_templates) = self.get_role_macro(node)
            new_templs = self.get_template_ids(owner_hostname, macro_templates) + tag_info['templates']
            if node.get('role') in ['VIRTUAL_MACHINE', 'EC2_INSTANCE']:
                hostgroups = self.get_group_ids(owner_hostname, macro_groups)
                hostgroups += self.get_project_to_group(owner_hostname, node)
                hostgroups += tag_info['hostgroups']
                hostgroups += tag_info['hostgroups_2']
            else:
                hostgroups = self.get_group_ids(owner_hostname, macro_groups)
            # Remove Duplicates
            new_templs = self.unique_listofdict(new_templs, 'templateid')
            hostgroups = self.unique_listofdict(hostgroups, 'groupid')

            to_clear = self.templates_to_clear(host, new_templs)

            update = {
                "hostid": host["hostid"],
                "status": status,
                "host": hostname,
                "name": visible_name,
                "groups": hostgroups,
                "templates": new_templs,
                "templates_clear": to_clear,
                "inventory": inventory,
                "macros": tag_info['macros'],

                # "proxy_hostid": self.zabbix_proxyid,
            }

            if int(self.config['zabbix'].get('update_proxy', 0)):
                update['proxy_hostid'] = self.prx_queue.get_next() if self.prx_queue else self.zabbix_proxyid
                proxy_addr = self.prx_id_addresses.get(int(update['proxy_hostid']), [self.zabbix_server, self.zabbix_port])
            else:
                proxy_addr = self.prx_id_addresses.get(int(host['proxy_hostid']), [self.zabbix_server, self.zabbix_port])

            self.zabbix_api.host.update(**update)
            self.logger.debug("[U] Zabbix host %s(%s, %s) was UPDATED with success!" % (visible_name, hostname, host["hostid"]))
            return (True, proxy_addr)
        except ZabbixAPIException as e:
            self.logger.error(
                'FAILED TO UPDATE host %s(%s, %s) in Zabbix: %s',
                node['name'], host['hostid'], hostname, e
            )
            return False


    def extra_inventory_data(self, node):
        inventory = {}
        if node.get('role') == "VIRTUAL_ROUTER":
            inventory = {
                'asset_tag': 'networkdomain',
                'chassis': 'hostname',
                'location': 'zonename',
                'contact': 'account',
                'hardware_full': 'serviceofferingname'
            }
        elif node.get('role') == "SYSTEM_VM":
            inventory = {
                'chassis': 'hostname',
                'location': 'zonename',
                'hardware_full': 'systemvmtype'
            }
        elif node.get('role') == "VIRTUAL_MACHINE":
            inventory = {
                'asset_tag': 'hypervisor',
                'chassis': 'hostname',
                'location': 'zonename',
                'model': 'instancename',
                'hardware_full': 'serviceofferingname',
                'contact': 'project',
                'contract_number': 'projectid'
            }

        for key, value in inventory.items():
            try:
                inventory[key] = node[value]
            except (KeyError, ValueError):
                inventory[key] = 'null'
        return inventory

    def get_role_macro(self, node):
        if node.get('role') == "VIRTUAL_ROUTER":
            macro_groups = self.MACRO_ROUTER_GROUPS
            macro_templates = self.MACRO_ROUTER_TEMPLATES
        elif node.get('role') == "SYSTEM_VM":
            macro_groups = self.MACRO_SYSTEM_VM_GROUPS
            macro_templates = self.MACRO_SYSTEM_VM_TEMPLATES
        else:
            macro_groups = self.MACRO_GROUPS
            macro_templates = self.MACRO_TEMPLATES
        return (macro_groups, macro_templates)

    def get_project_to_group(self, owner_hostname, node):
        group_names = self.get_macros_split(owner_hostname, self.MACRO_GROUPS)
        if group_names:
            project = node.get('project', False)
            if project:
                project = unidecode(project.decode('utf-8'))
                project_group = group_names[0] + '_' + project
                is_project = True
                return self.group_ids_from_names(owner_hostname, [project_group], is_project)
            else:
                return []
        else:
            self.logger.error("Macro %s needs to be defined in host %s!" % (self.MACRO_GROUPS, owner_hostname))
            return []

    def get_custom_group_tags(self, node):
        if self.config.get('cloudstack_tags', False):
            if self.config['cloudstack_tags'].get('custom_group_tags', False):
                return 0
            else:
                return []
        else:
            return []

    def get_tag_value(self, name, tags):
        tags_org = {i['key']: i['value'] for i in tags}
        return tags_org.get(self.config['cloudstack_tags'][name], 0)

    def role_to_instance_type(self, instance_type):
        rel = {
            'VirtualMachine': 'VIRTUAL_MACHINE',
            'DomainRouter': 'VIRTUAL_ROUTER',
            'SystemVm': 'SYSTEM_VM'
        }
        return rel.get(instance_type)

    def get_monitoring_tag(self, node):
        if node.get('role') in ['VIRTUAL_MACHINE', 'EC2_INSTANCE']:
            if node.get('tags', False):
                # '0'|'1' str if tag exists in cs(true), 0 int if tag not exists in CS (false)
                tag_monitoring = self.get_tag_value('monitoring', node['tags'])
                if not tag_monitoring:
                    shortcuts = self.config['cloudstack_tags']['shortcuts']
                    tag_monitoring = 0
                    for tag in node['tags']:
                        for k, v in shortcuts.iteritems():
                            if k == tag['key'] and tag['value'] == '1' and int(v.get('monitoring'),0):
                                tag_monitoring = 1
                                break
            else:
                tag_monitoring = 0
        else:
            tag_monitoring = 1
        return int(tag_monitoring)


    def delete_hosts(self, hosts):
        pass

    def delete_zabbix_hosts(self, node, owner_hostname, zbx_unchecked_hostids):
        if self.deleted_hosts_groupid:
            # move to "Not exist hosts" group old zabbix hosts
            for hostid in zbx_unchecked_hostids:
                target_host = self.zabbix_api.host.get(**{"output": ["host", "name"], "hostids": [hostid]})[0]
                # for the case of zabbix visible name is empty.
                now = '_' + datetime.today().strftime(self.TIME_FORMAT) + '_'
                target_visible_name = now + target_host["name"] if "name" in target_host else ""
                self.logger.info("Node %s(%s) was removed from CloudStack or had its monitoring tag removed. Moving it the deleted hosts group (%s)" % (target_host["name"], hostid, self.deleted_hosts_groupid[0]['groupid']))
                inventory = {
                    "name": self.adjust_string_length(node['name'], "", self.VISIBLE_NAME_MAX_LENGTH),
                    "type": self.type,
                    "tag": '_DELETED_' + owner_hostname,
                }
                # inventory.update(self.extra_inventory_data(node))
                self.zabbix_api.host.update(**{
                    "hostid": hostid,
                    "host":  now + target_host["host"],
                    "name": self.adjust_string_length(target_visible_name, "", self.VISIBLE_NAME_MAX_LENGTH),
                    "groups": self.deleted_hosts_groupid,
                    "status": 1,
                    "inventory":inventory,
                })
        else:
            # Delete host if group doesnt exist
            if zbx_unchecked_hostids:
                self.zabbix_api.host.delete(*zbx_unchecked_hostids)
                for hostid in zbx_unchecked_hostids:
                    self.logger.info("Node %s was removed from CloudStack or had its monitoring tag removed. It was deleted in Zabbix since there's no deleted hosts group" % hostid)

    def delete_zabbix_node(self, owner, node):
        host = self.zabbix_hostget(node['id'], ['hostid', 'name'])
        if not host:
            self.logger.warning("Couldnt delete host %s in Zabbix" % node['id'])
            return False

        if self.deleted_hosts_groupid:
            now = '_' + datetime.today().strftime(self.TIME_FORMAT) + '_'

            target_visible_name = now + host["name"] if "name" in host else ""
            inventory = {
                "name": self.adjust_string_length(node['name'], "", self.VISIBLE_NAME_MAX_LENGTH),
                "type": self.type,
                "tag": '_DELETED_' + owner,
            }
            inventory.update(self.extra_inventory_data(node))
            self.zabbix_api.host.update(**{
                "hostid": host['hostid'],
                "host":  now + node['id'],
                "name": self.adjust_string_length(target_visible_name, "", self.VISIBLE_NAME_MAX_LENGTH),
                "groups": self.deleted_hosts_groupid,
                "status": 1,
                "inventory":inventory,
            })
            self.logger.info("Node %s(%s) was removed from CloudStack or had its monitoring tag removed. Moving it the deleted hosts group (%s)" % (host['name'], host['hostid'], self.deleted_hosts_groupid[0]['groupid']))

        else:
            self.zabbix_api.host.delete(host['hostid'])
            self.logger.info("Node %s(%s) was removed from CloudStack or had its monitoring tag removed. It was deleted in Zabbix since there's no deleted hosts group" % (host['name'], host['hostid']))
        return True

    def zabbix_hostget(self, hostname, output):
        host = self.zabbix_api.host.get(**{'filter': {'host': hostname}, 'output': output})
        if host:
            return host[0]
        else:
            self.logger.debug("Host %s not found in Zabbix." % hostname)
            return None

    def random_filler(self, length):
        return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(length))

    def delete_zbx_host_simple(self, owner, host):
        self.logger.debug("Simple delete for Zabbix host %s(%s, %s)" % (host.get('name', ''), host['host'], host['hostid']))
        try:
            if self.deleted_hosts_groupid:
                now = '_' + datetime.today().strftime(self.TIME_FORMAT) + '_'
                hostname = now + host['host']
                name = now + host["name"] if "name" in host else ""
                name = self.adjust_string_length(name, '', self.VISIBLE_NAME_MAX_LENGTH)
                inventory = {'tag': '_DELETED_' + owner}

                self.zabbix_api.host.update(**{
                    "hostid": host['hostid'],
                    "host":  hostname,
                    "name": name,
                    "groups": self.deleted_hosts_groupid,
                    "status": 1,
                    "inventory":inventory,
                })
                self.logger.info("Node %s(%s) was removed from CloudStack or had its monitoring tag removed. Moving it the deleted hosts group (%s)" % (host.get('name', host['host']), host['hostid'], self.deleted_hosts_groupid[0]['groupid']))

            else:
                self.zabbix_api.host.delete(host['hostid'])
                self.logger.info("Node %s(%s) was removed from CloudStack or had its monitoring tag removed. It was deleted in Zabbix since there's no deleted hosts group" % (host.get('name', host['host']), host['hostid']))
            return True
        except ZabbixAPIException as e:
            self.logger.error("Failed to delete zabbix host: %s" % str(e))
            return False

    def templates_to_clear(self, host, new_templs):
        to_clear = []
        if host.get('parentTemplates'):
            old_templs = [{'templateid': i['templateid']} for i in host['parentTemplates'] if i.get('templateid')]
            for i in old_templs:
                if i not in new_templs:
                    to_clear.append(i)
        return to_clear

    def get_cs_vars(self, node):
        cs_vars = {}
        cs_vars['$_name_'] = node.get('name', '')
        cs_vars['$_zonename_'] = node.get('zonename', '')
        cs_vars['$_project_'] = node.get('project', '')

        ips = ['']
        vlans = ['']
        for interface in node['nic']:
            if interface.get('isdefault'):
                ips[0] = interface.get('ipaddress', '')
                vlans[0] = interface.get('broadcasturi', '')
            else:
                ips.append(interface.get('ipaddress', ''))
                vlans.append(interface.get('broadcasturi', ''))
        for index, ipaddr in enumerate(filter(None, ips)):
            cs_vars['$_ip' + str(index) + '_'] = ipaddr

        for index, vlan in enumerate(filter(None, vlans)):
            cs_vars['$_vlan' + str(index) + '_'] = vlan.lstrip('vlan://')

        return cs_vars
    def api_call_zabbix(self, call_list, cs_vars):
        """Sends a list of calls to the ZabbixAPI

        [description]

        Arguments:
            calls {[list]} -- list of dicts with api calls
                [{'class': '', 'method': '',  'params': ''}]
            cs_vars {[dict]} -- dict of vars from cloudstack
                {'$_name_': '$_ip0_': '', '$_ip1_': '', ...}

        Returns:
            bool -- [description]
        """

        if hasattr(self.zabbix_api, '__getattr__'):
            api = self.zabbix_api.__getattr__
        # To Support legacy zabbix_api module
        elif hasattr(self.zabbix_api, '__getattribute__'):
            api = self.zabbix_api.__getattribute__
        else:
            self.logger.error('Calls from zabbix_api tag are not supported!')
            return None

        self.logger.debug(
            'Available CloudStack vars for the next zabbix_api tag calls: %s'
            % str(cs_vars))
        ret = True
        for call in call_list:
            if isinstance(call['params'], dict):
                for key, value in call['params'].iteritems():
                    if not isinstance(call['params'][key], (list, dict)):
                        for cs_key, cs_val  in cs_vars.iteritems():
                            call['params'][key] = str(call['params'][key]).replace(cs_key, cs_val)
            elif isinstance(call['params'], list):
                for key, value in enumerate(call['params']):
                    if not isinstance(call['params'][key], (list, dict)):
                        for cs_key, cs_val  in cs_vars.iteritems():
                            call['params'][key] = str(call['params'][key]).replace(cs_key, cs_val)
            try:
                self.logger.debug('Executing %s' % call)
                if isinstance(call['params'], dict):
                    result = api(call['class']).__getattr__(call['method'])(**call['params'])
                elif isinstance(call['params'], list):
                    result = api(call['class']).__getattr__(call['method'])(*call['params'])
                else:
                    result = api(call['class']).__getattr__(call['method'])(call['params'])
                self.logger.debug('Call execution was successful!')
                self.logger_tags.debug(
                    '[ZABBIX_API][SUCCESS] Call: %s\nResult: %s' % (call, result))
            except ZabbixAPIException as e:
                self.logger.error("Call %s execution failed!" % call)
                self.logger_tags.error(
                    '[ZABBIX_API][FAIL] Call: %s\nResult: %s' % (call, str(e)))
                ret = False
        return ret

