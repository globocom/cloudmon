# -*- coding: utf-8 -*-

"""
cache
----------------------------------

This module provides a Redis Cache object.
"""

import sys
import pickle
from functools import wraps

import redis

from cloudmon.connector.errors import CacheMiss, CacheError
# from errors import CacheMiss, CacheError

from cloudmon.utils.log import logging

logger = logging.getLogger(__name__)
# logger.setLevel(logging.getLevelName('DEBUG'))
# logger.addHandler(logging.StreamHandler(sys.stdout))


class Cache(object):
    """Redis Cache Object """

    SUPPORTED_FUNCS = {
        'listVirtualMachines': 'vms',
        'listRouters': 'vrouters',
        'listProjects': 'projects',
    }

    RESOURCES_TO_SESSION = {
        'VirtualMachine': 'vms',
        'DomainRouter': 'vrouters',
        'SystemVm': 'sysvms',
        'Project': 'projects',
    }

    def __init__(self, host='localhost', port=6379, password=None, save=None):
        self.conn = redis.StrictRedis(host=host, port=port, password=password)
        if self.ping():
            logger.debug('Successfully connected to Redis Server!')
            if save is not None:
                self.conn.config_set('save', save)
            self.flush()
        else:
            raise CacheError('Failed to connect to Redis Server!')

    def ping(self):
        """Pings Redis Server. Returns True or False"""
        try:
            return self.conn.ping()
        except redis.RedisError:
            return False

    def store(self, pairs):
        """Stores each key/value of a dict as key/value in redis.

        Values are serialized before storage using pickle.
        Keyword Arguments:
            pairs {dict} -- dict to be stored
        """
        if not isinstance(pairs, dict) or not pairs:
            raise TypeError('Argument pairs must be a non empty dict. %s', str(pairs))

        pairs = {k: pickle.dumps(v) for k, v in pairs.iteritems()}

        try:
            if self.conn.mset(pairs):
                logger.debug('Pairs successfully stored in Redis!')
                return True
            else:
                return False
        except redis.RedisError as e:
            logger.error('Failed to store pairs in Redis: %s', e)
            return False

    def get(self, key):
        """Gets a key from Redis and deserializes it."""
        try:
            value = self.conn.get(key)
            if value is None:
                raise CacheMiss('Key {0} doesn\'t exist in cache'.format(key))
            value = pickle.loads(value)
            logger.debug('Value retrieved from Redis with success!')
            return value
        except (redis.RedisError, pickle.PickleError) as e:
            # logger.error('Failed to retrieve/unpack value from Redis: %s', e)
            raise CacheError(
                'Failed to retrieve/unpack value from Redis: {0}'.format(e))

    def create_id(self, owner, resource, id_=None):
        """Concats id for virtual artifact"""
        if resource in self.RESOURCES_TO_SESSION.keys():
            session = self.RESOURCES_TO_SESSION[resource]
        else:
            session = resource

        if session in ['vms', 'vrouters', 'sysvms', 'projects'] and id_:
            return owner + ':' + session + ':' + id_
        elif session == 'not_collected_projs' and not id_:
            return owner + ':' + session
        else:
            raise TypeError('Couldn\'t generate id.')

    def get_argument(self, key, arg):
        pass

    def store_infra(self, owner, infra):
        """Prepares a infra dict to be stored on Redis.

        Arguments:
            owner {str} -- owner name to be appended to the key
            infra {dict} -- dict that will be stored in Redis
        """
        if not self.ping():
            logger.error('Redis Cache is not responding.')
            return False
        to_cache = {}
        for session, items in infra.items():
            if session in ['vms', 'vrouters', 'sysvms', 'projects']:
                for i in items:
                    if i.get('id'):
                        id_ = owner + ':' + session + ':' + i['id']
                        to_cache[id_] = i
                id_ = owner + ':' + session + ':' 'total'
                to_cache[id_] = len(items)
            elif session == 'not_collected_projs':
                id_ = owner + ':' + session
                to_cache[id_] = items
        self.flush_filtered(owner + ':*')
        return self.store(to_cache)

    def get_artifact(self, owner, session, id_=''):
        """Concats the input params to form an id and calls a get"""
        if session in ['vms', 'vrouters', 'sysvms', 'projects'] and id_:
            art_id = str(owner) + ':' + session + ':' + str(id_)
        elif session == 'not_collected_projs' and not id_:
            art_id = str(owner) + ':' + session
        else:
            raise TypeError('Wrong argumentation')
        return self.get(art_id)

    def flush(self):
        """Deletes all keys"""
        self.conn.flushall()

    def flush_filtered(self, filter_by):
        """Deletes keys specified by filter"""
        if not self.ping():
            logger.error('Redis Cache is not responding.')
            return False
        keys = self.conn.keys(filter_by)
        return self.conn.delete(keys)

    def update(self, params):
        """Updates one or more fields of the cached objects.

        Arguments:
            params {dict} -- keys of the dicts are the ids of the objects to be
            updated. Its values are a dict with the new keys/values

        Returns:
            dict with status for each update (True or error msg) or False if
            update failed
        """
        if not isinstance(params, dict) or not params:
            raise TypeError('Argument params must be a non empty dict.')
        to_store = {}
        # ret = params
        ret = {}
        for id_, conf in params.iteritems():
            try:
                art = self.get(id_)
                if not isinstance(conf, dict) or not conf:
                    raise TypeError('Conf must be a non empty dict.')
                for k, v in conf.iteritems():
                    art[k] = v
                to_store[id_] = art
                ret[id_] = True
            except (CacheMiss, CacheError) as e:
                ret[id_] = e
        if to_store and self.store(to_store):
            return ret
        else:
            return False

    def update_status(self, owner, resource, id_, state):
        """Update status of virtual artifact"""
        cache_id = self.create_id(owner, resource, id_)
        update = self.update({cache_id:{'state':state}})

        if update and update[cache_id] is True:
            return True
        else:
            return False

    def delete_artifact(self):
        """Delete a virtual artifact"""
        pass

    def create_artifact(self):
        """Create a virtual artifact"""
        pass

def get_cached(cache, owner):
    """ Function to decorate CloudStack API functions and get objs from
    the Cache

        Arguments:
            cache {obj} -- obj from class Cache
            owner {str} -- owner name
    """
    def decorator(function):
        @wraps(function)
        def function_wrapper(*args, **kwargs):
            session = cache.SUPPORTED_FUNCS.get(function.func_name)
            id_ = kwargs.get('id')
            if cache.ping() and session and id_:
                try:
                    return cache.get_artifact(
                        owner=owner,
                        session=session,
                        id_=id_
                    )
                except (CacheError, CacheMiss) as e:
                    logger.error('%s. Will do an API call.', e)
            return function(*args, **kwargs)
        return function_wrapper
    return decorator
