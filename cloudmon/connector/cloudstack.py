# -*- coding: utf-8 -*-

import traceback
import json
import threading
import time

from datetime import datetime

import cs

from cloudmon.connector.zabbix import ZabbixAPIException
from cloudmon.connector.base import BaseConnector
from cloudmon.connector.cloudstack_queue import CloudStackQueue

from cloudmon.utils.log import logging


def get_last_exec_cs():
    return 0

class CloudStackConnector(BaseConnector):

    EXTRA_PARAMS = {}

    MAX_THREADS = 10

    def __init__(self, config):
        self.type = "cloudstack"
        self.threads_proj = []
        super(CloudStackConnector, self).__init__(config)
        self.logger = logging.getLogger("cloudmon." + self.type)
        self.monitored = self.config.get('monitored_instances', {})
        self.logger.info(
            "The following types of instance will be monitored as: %s",
            self.monitored
        )
        self.logger.info(
            "Timeout for CloudStack HTTP(s) requests is %ss",
            self.config['cloudstack']['timeout']
        )
        ssl_config = self.config['ssl']
        if ssl_config['verify_cloudstack'] and ssl_config['ca_bundle']:
            self.verify_cs = ssl_config['ca_bundle']
            self.logger.info(
                'All HTTPS requests to CloudStack are gonna be '
                'verified! Cert Bundle: %s',
                self.verify_cs
            )
        elif ssl_config['verify_cloudstack']:
            self.verify_cs = True
            self.logger.info(
                'All HTTPS requests to CloudStack are gonna be verified!'
            )
        else:
            self.verify_cs = False
            self.logger.warning(
                'According to your configuration, all HTTPS requests to '
                'CloudStack are not gonna be verified!'
            )


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
        cs_api = self.get_cs_api(hostname)
        self.logger.debug('Command received: %s', command)
        if not cs_api:
            self.logger.error('Failed to connect to CloudStack API.')
            return {'result': False, 'message': 'Failed to connect to CloudStack API'}

        if command == 'api':
            self.metrics['monitor'].start()
            result = self.monitor(hostname, cs_api)
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
                queue = CloudStackQueue(hostname, params, self.config, cs_api)
            else:
                self.logger.warning(
                    'Zabbix Macro Queue params (%s, %s, %s) not found in host '
                    '%s. Cant connect to the CloudStack Event Queue.'
                    % (
                        self.MACRO_QUEUE_URL, self.MACRO_QUEUE_QUEUE,
                        self.MACRO_QUEUE_EXCHANGE, hostname))
                return None
            try:
                queue.process()
            except Exception as e:
                self.logger.error('Failed to process cloudstack queue: %s', e)
                self.logger.error(traceback.format_exc())
                return None
        else:
            return {"result": False, "message": "Command %s not available" % command}


    def get_cs_api(self, hostname):
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
        url = self.get_user_macro(owner_hostname, self.MACRO_URL)

        if url and secret and key:
            cs_api = cs.CloudStack(
                url,
                key,
                secret,
                timeout=self.config['cloudstack']['timeout'],
                verify=self.verify_cs,
            )
            try:
                cs_api.getUser(userapikey=cs_api.key)
                self.logger.info('CloudStack API Login was successful!')
                return cs_api
            except Exception as e:
                self.logger.error('CloudStack API Login failed: %s', e)
                return False
        else:
            self.logger.error(
                'Failed to get credentials from zabbix or macros not found.')
            return False

    def filter_result(self, result, filters):
        """ Filters a CloudStack API result (list of dicts), returning
        only the dict fields specified in fields
        """
        if not filters:
            return result
        new_res = []
        for val in result:
            new_res.append({k: v for k, v in val.iteritems() if k in filters})
        return new_res

    def get_infra(self, cs_api, owner):
        infra = {
            'vms': [],
            'vrouters': [],
            'sysvms': [],
            'projects': []
        }

        if self.monitored['virtual_machines'] in ['tagged', 'all']:
            proj_fields = ['name', 'id', 'vmtotal']
            vm_fields = [
                'displayname', 'hostname', 'hypervisor', 'id', 'instancename',
                'name', 'nic', 'project', 'projectid', 'serviceofferingname',
                'state', 'tags', 'zonename', 'templatename', 'role', 'account'
            ]

            infra['projects'] = self.get_projects(cs_api, proj_fields)
            infra['vms'], infra['not_collected_projs'] = self.get_vms(
                cs_api, owner,
                projects=infra['projects'],
                fields=vm_fields,
                monitor=self.monitored['virtual_machines'],
            )


        if self.monitored['virtual_routers'] in ['all']:
            infra['vrouters'] = self.get_vrouters(cs_api)

        if self.monitored['system_vms'] in ['all']:
            infra['sysvms'] = self.get_sysvms(cs_api)

        return infra

    def get_projects(self, cs_api, fields=None, monitor='tagged'):
        """Get projects from CloudStack returning only the fields
        specified in fields
        """
        if fields is None:
            fields = []
        if not self.config['dev_mode'].get('projectid'):
            try:
                params = {'listall': 'True'}
                params.update(self.EXTRA_PARAMS)
                projects = cs_api.listProjects(**params).get('project', [])
                projects = self.filter_result(projects, fields)
                self.logger.info(
                    'Successfully got %s PROJECTS from CloudStack',
                    len(projects)
                )
                self.logger.debugv('PROJECTS:\n%s', projects)
            except Exception as e:
                self.logger.error('Couldnt get project list: %s', e)
                projects = []
        else:
            raise NotImplementedError(
                "Dev mode not supported! Check config file!")

        return projects

    def get_vrouters(self, cs_api, fields=None):
        """Get Virtual Routers from CloudStack returning only the fields
         specified in fields
        """
        if fields is None:
            fields = []
        try:
            params = {'listall': 'True'}
            routers = cs_api.listRouters(**params).get('router', [])
            routers = self.filter_result(routers, fields)
            self.logger.info(
                'Successfully got %s VIRTUAL ROUTERS from CloudStack',
                len(routers)
            )
            self.logger.debugv('VIRTUAL ROUTERS:\n%s', routers)
        except Exception as e:
            self.logger.error('Couldnt get VIRTUAL ROUTERS: %s', e)
            routers = []
        return routers

    def get_sysvms(self, cs_api, fields=None):
        """Get System VMs (SSVM and ConsoleProxy) from CloudStack
        returning only the fields specified in fields
        """
        if fields is None:
            fields = []
        try:
            sysvms = cs_api.listSystemVms().get('systemvm', [])
            sysvms = self.filter_result(sysvms, fields)
            self.logger.info(
                'Successfully got %s SYSTEM VMs from CloudStack',
                len(sysvms)
            )
        except Exception as e:
            self.logger.error('Couldnt get Sytem VMs: %s', e)
            sysvms = []
            return sysvms

        try:
            ssvm = cs_api.listHosts(
                type='SecondaryStorageVM',
                details='min').get('host', [])
            console_proxy = cs_api.listHosts(
                type='ConsoleProxy',
                details='min').get('host', [])
            hosts = ssvm + console_proxy
            count = 0
            for i in sysvms:
                i['role'] = 'SYSTEM_VM'
                for j in hosts:
                    if i['name'] == j['name']:
                        i['agentstate'] = j['state']
                        count += 1
                        break
            if count == len(sysvms):
                self.logger.debug(
                    'Successfully got agentstate for every SYSTEM VM (%s/%s)',
                    count, len(sysvms))
            else:
                self.logger.warning(
                    'Couldnt get agentstate for every SYSTEM VM (%s/%s)',
                    count, len(sysvms))
        except Exception as e:
            self.logger.error('Couldnt get Hosts for agentstate: %s', e)

        self.logger.debugv('SYSTEM VMs:\n%s', sysvms)
        return sysvms

    def check_thread_alive(self, threads):
        for thread in threads:
            if not thread.isAlive():
                threads.remove(thread)

    def prepare_thread(
            self, thread_name, cs_api, params_cs, proj_name,
            proj_id, fields, monitor, results,
            not_collected_projs, successful_projs):

        # self.logger.debug('Preparing Thread: %s => %s', thread_name)
        alive_thread_names = []
        for thread in self.threads_proj:
            if thread.isAlive():
                alive_thread_names.append(thread.name)
            else:
                self.threads_proj.remove(thread)
        if thread_name in alive_thread_names:
            self.logger.debug("Thread %s already running. skipped." % thread_name)
        else:
            self.logger.debug("Starting %s thread..." % thread_name)
            th = threading.Thread(
                name=thread_name,
                target=self.get_vms_thread,
                args=(cs_api, params_cs, proj_name,
                    proj_id, fields, monitor, results,
                    not_collected_projs, successful_projs)
            )
            # self.logger.debug('Starting Thread: %s', th)
            th.start()
            self.threads_proj.append(th)
        # self.logger.debug("Active threads: %s" % [{thread.name: thread.isAlive()} for thread in self.threads_proj])


    def get_vms(
            self, cs_api, owner, projects=None, fields=None,
            no_proj_vms=True, monitor='tagged'):
        """Get vms that exists in the defined projects
        no_proj_vms gets vms without project

        """
        if fields is None:
            fields = []

        if projects is None:
            projects = []

        if no_proj_vms:
            projects.append({'id': None, 'name': 'VMs without project'})

        params_mon = {}
        if monitor == 'tagged':
            self.logger.info(
                'Hosts with any of the following tags active %s will be'
                ' monitored', self.mon_tags
            )
            for idx, tag in enumerate(self.mon_tags):
                params_mon['tags[{0}].key'.format(idx)] = tag
                params_mon['tags[{0}].value'.format(idx)] = '1'

        total_vms = []
        not_collected_projs = []
        successful_projs = []
        failed_projs = 0
        null_projs = 0
        results = {}

        for proj in projects:
            proj_name = proj.get('name', 'No name found')

            if int(proj.get('vmtotal', 1)) <= 0:
                self.logger.debug(
                    'Project %s(%s) doesnt have any VMs',
                    proj_name, proj['id'])
                null_projs += 1
            else:
                params = {
                    'listall': 'True',
                    'projectid': proj['id'],
                    # 'details': 'nics'
                }
                params.update(params_mon)
                params.update(self.EXTRA_PARAMS)

                thread_name = owner + '_' + str(proj.get('id', proj.get('name', 'NoID')))
                self.prepare_thread(
                    thread_name, cs_api, params, proj_name,
                    proj['id'], fields, monitor, results,
                    not_collected_projs, successful_projs
                )

            self.check_thread_alive(self.threads_proj)
            while len(self.threads_proj) > self.MAX_THREADS:
                time.sleep(1)
                self.check_thread_alive(self.threads_proj)
                self.logger.debugv('Max thread reached %s', len(self.threads_proj))
            self.logger.debugv('End of thread loop, %s', self.threads_proj)

        self.check_thread_alive(self.threads_proj)
        while len(self.threads_proj) > 0:
            time.sleep(1)
            self.check_thread_alive(self.threads_proj)
            self.logger.debugv('Waiting for threads to complete %s', self.threads_proj)

        self.logger.debugv('End of exec loop %s', self.threads_proj)
        n_proj = len(projects)-1 if no_proj_vms else len(projects)

        for i in results.values():
            total_vms.extend(i)

        self.logger.info(
            'Successfully got %s (%s) VMs from %s projects in CloudStack '
            '(out of %s total projects, %s failed and %s had no VMs)',
            len(total_vms), monitor, len(successful_projs),
            n_proj, len(not_collected_projs), null_projs
        )

        if len(not_collected_projs):
            self.logger.error(
                'Failed to get VMs from projects, its VMs won\'t '
                'be deleted or updated: %s', not_collected_projs
            )

        return (total_vms, not_collected_projs)


    def get_vms_thread(
            self, cs_api, params_cs, proj_name, proj_id, fields,
            monitor, result, not_collected_projs, successful_projs):

        try:
            vms = cs_api.listVirtualMachines(**params_cs)
            vms = vms.get('virtualmachine', [])
            result[proj_id] = self.filter_result(vms, fields)
            for i in result[proj_id]:
                i['role'] = 'VIRTUAL_MACHINE'

            self.logger.debug(
                'Successfully got %s (%s) VMs from project %s(%s)',
                len(result[proj_id]), monitor, proj_name, proj_id)
            self.logger.debugv('VMs:\n%s', result[proj_id])
            successful_projs.append(proj_name)

        except Exception as e:
            self.logger.error(
                'Couldnt get VMs from project %s: %s', proj_name, e)
            not_collected_projs.append(proj_name)




    def monitor(self, owner, cs_api):
        monitor_operations = self.get_macros_split(owner, self.MACRO_MON_OPS)
        if not monitor_operations:
            monitor_operations = self.config['cloudmon']['monitor_operations']
        self.logger.info(
            'The api thread will do the following operations: %s',
            monitor_operations
        )

        try:
            self.metrics['cloudstack'].start()
            infra = self.get_infra(cs_api, owner)

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

            cs_hosts = infra['vms'] + infra['sysvms'] + infra['vrouters']
            metrics_cloudstack = self.metrics['cloudstack'].stop()
            self.zabbix_sender(owner, "metrics.cloudstack", metrics_cloudstack)

            self.zabbix_sender(owner, "cloudmon.cloudstackConnection", "Succeeded")
        except Exception as e:
            self.zabbix_sender(owner, "cloudmon.cloudstackConnection", str(e))
            self.logger.error("Failed to connect to CloudStack: %s" % str(e))
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
        cs_hosts = {i['id']: i for i in cs_hosts}

        zbx_only = list(set(zbx_hosts.keys()) - set(cs_hosts.keys()))
        cs_only = list(set(cs_hosts.keys()) - set(zbx_hosts.keys()))
        in_cs_zbx = list(set(zbx_hosts).intersection(set(cs_hosts)))

        zbx_only = list(set(zbx_only) - set(not_remove))

        # self.logger.info( '\n#zbx_only\n%s, \n#cs_only\n%s, \n#both\n%s', zbx_only, cs_only, in_cs_zbx)
        # self.logger.info( '%s, %s, %s', len(zbx_only), len(cs_only), len(in_cs_zbx))
        valid_states = self.STATES_ENABLED + self.STATES_DISABLED

        cre_ids = {}
        upd_ids = {}
        del_ids = {}

        # Create
        if 'create' in monitor_operations:
            for hostname in cs_only:
                state = cs_hosts[hostname].get('state', 'NOT FOUND')
                name = cs_hosts[hostname].get('name', hostname)
                if state in valid_states:
                    self.logger.debug(
                        '%s(%s) exists only in CloudStack. CloudMon will '
                        'attempt to create it in Zabbix',
                        name, hostname
                    )
                    cre_id = self.create_zabbix_host(
                        owner, hostname, cs_hosts[hostname])
                    if cre_id:
                        cre_ids[cre_id] = [name, hostname]
                else:
                    self.logger.debug(
                        '%s(%s) exists only in CloudStack but has state %s. '
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
            if self.deleted_hosts_groupid:
                for hostname in zbx_only:
                    now = '_' + datetime.today().strftime(self.TIME_FORMAT) + '_'
                    name = zbx_hosts[hostname].get('name', hostname)
                    zbx_name = self.adjust_string_length(now + name, '', self.VISIBLE_NAME_MAX_LENGTH)
                    inventory = {
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
            for hostname in in_cs_zbx:
                hostid = zbx_hosts[hostname]['hostid']
                name = zbx_hosts[hostname].get('name', hostname)
                state = cs_hosts[hostname].get('state', 'NOT FOUND')

                self.logger.debug('#updating %s(%s, %s)',
                    name, hostid, hostname
                )

                result = self.update_zabbix_host(
                    owner, hostname, cs_hosts[hostname], zbx_hosts[hostname])

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
                            if cs_hosts[hostname].get('role') == "SYSTEM_VM":
                                self.zabbix_sender(hostname, "systemvm.state", cs_hosts[hostname]['state'], proxy_addr[0], proxy_addr[1])
                                self.zabbix_sender(hostname, "systemvm.agentstate", cs_hosts[hostname].get('agentstate', 'null'), proxy_addr[0], proxy_addr[1])
                            else:
                                self.zabbix_sender(hostname, "instance.state", cs_hosts[hostname]['state'], proxy_addr[0], proxy_addr[1])


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
            self.logger.info('CREATED hosts in Zabbix: %s', json.dumps(cre_ids, indent=2))
        if upd_ids:
            self.logger.info('UPDATED hosts in Zabbix: %s', json.dumps(upd_ids, indent=2))

        len_cre, len_upd, len_del = len(cre_ids), len(upd_ids), len(del_ids)
        self.logger.info(
            'In total CloudMon created %s, updated %s and deleted %s '
            'hosts from Zabbix', len_cre, len_upd, len_del
        )
        metrics_zabbixloop = self.metrics['zabbixloop'].stop()
        self.zabbix_sender(owner, "metrics.zabbixloop", metrics_zabbixloop)
        self.zabbix_sender(owner, "metrics.apicreates", len_cre)
        self.zabbix_sender(owner, "metrics.apiupdates", len_upd)
        self.zabbix_sender(owner, "metrics.apideletes", len_del)

        return True



