"""
Validation schemas and rules
"""

from parse import *
from zabbix_macros import ZABBIX_MACROS

RULE_PORT = {
    'type': 'integer',
    'coerce': int,
    'min': 0,
    'max': 65535,
    'required': True
}

RULE_IPV4 = {
    'type': 'string',
    'coerce': unquote,
    #'regex': ipv4re,
    'default': '127.0.0.1'
}

RULE_MACRO = {
    'type': 'string',
    'coerce': unquote,
    'allowed': ZABBIX_MACROS,
    # 'regex': '^\{\$[A-Z0-9_\.]+(?:\:.+)?\}$',
}

RULE_ADDRESS = {
    'type': 'string',
    'coerce': unquote,
    'regex': '^[^:]+:\d{1,5}$',
    'default': '127.0.0.1:10051',
}

RULE_BOOL = {
    'type': 'boolean',
    'coerce': to_bool,
    'default': False
}

RULE_BOOL_TRUE = {
    'type': 'boolean',
    'coerce': to_bool,
    'default': True
}

RULE_LEVELS = {
    'type': 'string',
    'allowed': ['DEBUG-V', 'DEBUG', 'INFO', 'WARNING'],
    'default': 'INFO',
    'coerce': unquote,
}

RULE_EQP_VM = {
    'type': 'string',
    'coerce': unquote,
    'allowed': ['all', 'tagged', 'no'],
    'default': 'tagged',
}

RULE_EQP_MON = {
    'type': 'string',
    'coerce': unquote,
    'allowed': ['all', 'no'],
    'default': 'no'
}

RULE_ROTATION = {
    'type': 'integer',
    'coerce': int,
    'min': 0,
    'default': 9
}

RULE_LIST_OPERATIONS = {
    'type': 'list',
    'coerce': str_to_list,
    'allowed': ['create', 'update', 'delete'],
    'default': 'create, update, delete',
}

RULE_LIST_DEFAULT = {
    'type': 'list',
    'coerce': str_to_list,
    'default': []
}

RULE_LIST_REQUIRED = {
    'type': 'list',
    'coerce': str_to_list,
    'required': True
}

RULE_STR_DEFAULT = {
    'type': 'string',
    'coerce': unquote,
    'default': ''
}

RULE_STR_REQUIRED = {
    'type': 'string',
    'coerce': unquote,
    'required': True
}


SCHEMA_BL = {
    'names': RULE_LIST_DEFAULT,
    'regexps': RULE_LIST_DEFAULT,
}


NOT_ALLOWED_PROXY = []

SCHEMA = {

    'host_macros': {
        'type': 'dict',
        'default': {},
        'keyschema': RULE_MACRO,
        'valueschema': {'type': 'string', 'coerce': unquote}
    },

    'env': {
        'type': 'dict',
        'default': {},
        'keyschema': {'type': 'string'},
        'valueschema': {'type': 'string', 'coerce': unquote}
    },
    'ssl': {'type': 'dict', 'default': {}, 'schema': {
        'verify_zabbix': RULE_BOOL_TRUE,
        'verify_cloudstack': RULE_BOOL_TRUE,
        'ca_bundle': {'type': 'string', 'coerce': unquote, 'default': ''},
    }},
    'cloudmon': {'type': 'dict', 'required': True, 'schema': {
        'listen_address': RULE_IPV4,
        'listen_port': RULE_PORT,
        'monitor_operations': RULE_LIST_OPERATIONS,
        'use_cache': RULE_BOOL,
    }},
    'dev_mode': {
        'type': 'dict',
        'default': {},
    },
    'cloudstack': {'type': 'dict', 'default': {}, 'schema': {
        'timeout': {'type': 'integer', 'coerce': int, 'default': 300},
    }},
    'zabbix': {'type': 'dict', 'required': True, 'schema': {
        'zabbix_password': RULE_STR_REQUIRED,
        'zabbix_sender': {'type': 'string', 'coerce': unquote, 'default': '/usr/bin/zabbix_sender'},
        'zabbix_server': {'type': 'string', 'coerce': unquote, 'default': '127.0.0.1'},
        'zabbix_user': RULE_STR_REQUIRED,
        'deleted_hosts_group': RULE_STR_DEFAULT,
        'frontend_url': RULE_STR_REQUIRED,
        'update_proxy': RULE_BOOL,
        'zabbix_port': RULE_PORT,
        'proxies': {
            'type': 'dict',
            'default': {},
            'keyschema': {'type': 'string'},
            'valueschema': {'type': 'dict', 'schema': {
                'weight': {'type': 'integer', 'coerce': int, 'required': True},
                'address': RULE_ADDRESS,
            }}
        }
    }},
    'logging': {'type': 'dict', 'default': {}, 'schema': {
        'log_file': {'type': 'string', 'coerce': unquote, 'default': '/tmp/cloudmon.log'},
        'zabbix_api_log_file': {'type': 'string', 'coerce': unquote, 'default': ''},
        'queue_log_file': {'type': 'string', 'coerce': unquote, 'default': '/tmp/cloudstack_queue.log'},
        'log_level': RULE_LEVELS,
        'number_of_logrotations': RULE_ROTATION,
        'max_logsize_in_bytes': {'type': 'integer', 'coerce': parse_bytes_suffix, 'default': '1048576'},

    }},
    'blacklisted': {'type': 'dict', 'default': {}, 'schema': {
        'hostgroups': {'type': 'dict', 'default':{}, 'schema': SCHEMA_BL},
        'templates': {'type': 'dict', 'default':{}, 'schema': SCHEMA_BL},
        'macros': {'type': 'dict', 'default':{}, 'schema': SCHEMA_BL},
        'classes': {'type': 'dict', 'default':{}, 'schema': SCHEMA_BL},
        'methods': {'type': 'dict', 'default':{}, 'schema': SCHEMA_BL},

    }},
    'monitored_instances': {'type': 'dict', 'required': True, 'schema': {
        'virtual_machines': RULE_EQP_VM,
        'system_vms': RULE_EQP_MON,
        'virtual_routers': RULE_EQP_MON
    }},

    'cloudstack_tags': { 'type': 'dict', 'unique_dict_values': True, 'default': {}, 'schema': {
        'monitoring': {'type': 'string', 'coerce': unquote, 'default': 'monitoring'},
        'hostgroups': {'type': 'string', 'coerce': unquote, 'default': 'hostgroups'},
        'hostgroups_2': {'type': 'string', 'coerce': unquote, 'default': 'hostgroups_2'},
        'templates': {'type': 'string', 'coerce': unquote, 'default': 'templates'},
        'macros': {'type': 'string', 'coerce': unquote, 'default': 'macros'},
        'zabbix_api': {'type': 'string', 'coerce': unquote, 'default': 'zabbix_api'},
        'shortcuts': {
            'type': 'dict',
            'default': {},
            'keyschema': {'type': 'string'},
            'valueschema': {'type': 'dict', 'schema': {  # Not created auto
                'templates': {'type': 'list', 'coerce': str_to_list},
                'monitoring': {'type': 'string', 'coerce': unquote},
                'hostgroups': {'type': 'list', 'coerce': str_to_list},
                'hostgroups_2': {'type': 'list', 'coerce': str_to_list},
                'macros': {'type': 'list', 'coerce': parse_zabbix_macro},
                'zabbix_api': {'type': 'list', 'coerce': parse_zabbix_api, 'schema': {
                    'type':'dict', 'schema': {
                        'class': {'type': 'string'},
                        'method': {'type': 'string'},
                        'params': {}
                    }
                }}
            }}
        }
    }}
}
