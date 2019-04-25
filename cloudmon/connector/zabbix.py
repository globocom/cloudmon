# -*- coding: utf-8 -*-

"""
zabbix
----------------------------------

Zabbix stuff for `cloudmon`.
"""

import re

from time import time, sleep
from pyzabbix import ZabbixAPI, ZabbixAPIException

from cloudmon.utils.log import logging

logger = logging.getLogger(__name__)

REQUEST_DELAY = 0.1


class ZabbixAPICM(ZabbixAPI):
    """This derived class is an extention to ZabbixAPI that adds a timer
    to not let the session expire"""

    def __init__(self,
                 server='http://localhost/zabbix',
                 session=None,
                 use_authenticate=False,
                 timeout=None,
                 session_expiration=7200):
        """This overrides the original ZabbixAPI __init__ method.
        It adds new variables that will be used in the new class"""
        super(ZabbixAPICM, self).__init__(
            server,
            session,
            use_authenticate,
            timeout
        )
        self.param_user = ''
        self.param_password = ''
        self.session_expiration = session_expiration
        self.auth_start = 0

    def login(self, user='', password=''):
        """This overrides the original ZabbixAPI login method.
        It starts a timer after the login process to not let the
        token expire"""
        super(ZabbixAPICM, self).login(user=user, password=password)
        if self.auth:
            self.param_user = user
            self.param_password = password
            self.auth_start = time()

    def do_request(self, method, params=None):
        """This overrides the original ZabbixAPI do_request method.
        It verifies how long the token exists before doing the request
        and generates a new one in case it is expired"""
        bypass_methods = [
            'user.login', 'user.logout', 'user.authenticate', 'apiinfo.version'
        ]
        if not self.auth_start or method in bypass_methods:
            sleep(REQUEST_DELAY)
            return super(ZabbixAPICM, self).do_request(method, params)

        else:
            token_exists = time() - self.auth_start
            if token_exists < self.session_expiration:
                logger.debugv(
                    'Auth token exists for less than %ss (%ss), '
                    'will proceed doing the request.',
                    self.session_expiration, token_exists
                )
                try:
                    sleep(REQUEST_DELAY)
                    return super(ZabbixAPICM, self).do_request(method, params)

                except ZabbixAPIException as e:
                    mat = re.search(
                        r'Session terminated, re-login', e.args[0], flags=re.I)
                    if e.args[1] == -32602 and mat:
                        self.session_expiration *= 0.75
                        logger.debugv(
                            'Session was terminated, exception found: %s\n'
                            'Will do a new login to generate a new token '
                            'and proceed doing the request. '
                            'session_expiration will have a new value of %s',
                            e, self.session_expiration
                        )
                        self.login(self.param_user, self.param_password)
                        sleep(REQUEST_DELAY)
                        return super(ZabbixAPICM, self).do_request(
                            method, params
                        )
                    else:
                        raise e
            else:
                logger.debugv(
                    'Auth token exists for longer than %ss (%ss), '
                    'will logout and do a new login to generate a new token '
                    'and proceed doing the request.',
                    self.session_expiration, token_exists
                )
                try:
                    super(ZabbixAPICM, self).do_request('user.logout')
                except ZabbixAPIException:
                    pass
                self.login(self.param_user, self.param_password)
                sleep(REQUEST_DELAY)
                return super(ZabbixAPICM, self).do_request(method, params)
