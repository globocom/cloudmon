# -*- coding: utf-8 -*-

"""This module contains functions and objects related to log treatment
and creation.
"""
import sys
import logging
from logging.handlers import RotatingFileHandler


logging.addLevelName(9, "DEBUG-V")
def debugv(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    if self.isEnabledFor(9):
        self._log(9, message, args, **kws)

logging.Logger.debugv = debugv

def set_loggers(config, stdout=False):
    """Creates different log handlers for CloudMon"""

    # urllib3 logs
    logging.captureWarnings(True)
    # logging.getLogger("urllib3").setLevel(9)

    # Default logs
    log_level = config["logging"].get('log_level', 'INFO')
    log_file = config["logging"].get('log_file', '/tmp/cloudmon.log')
    log_format = '[%(asctime)s] %(threadName)s - %(levelname)s: %(message)s'
    formatter = logging.Formatter(log_format)

    logsize = config["logging"].get('max_logsize_in_bytes', 3145728) # 3MB default logsize
    logrotations = config["logging"].get('number_of_logrotations', 15)

    if not stdout:
        handler = RotatingFileHandler(log_file, maxBytes=int(logsize), backupCount=int(logrotations))
    else:
        handler = logging.StreamHandler(sys.stdout)

    handler.setLevel(9)
    handler.setFormatter(formatter)

    logger = logging.getLogger('cloudmon')

    # get log level from levelname
    logger.setLevel(logging.getLevelName(log_level))
    logger.addHandler(handler)

    # Logs from Zabbix Module
    logger_zbx = logging.getLogger('zabbix')
    logger_zbx.setLevel(logging.getLevelName(log_level))
    logger_zbx.addHandler(handler)

    # Logs from Cache Module
    logger_cache = logging.getLogger('cache')
    logger_cache.setLevel(logging.getLevelName(log_level))
    logger_cache.addHandler(handler)

    # CloudStack Queue logs
    if config['logging']['queue_log_file']:
        formatter = logging.Formatter('[%(asctime)s]: %(message)s')
        log_file = config['logging']['queue_log_file']

        if not stdout:
            handler_csq = RotatingFileHandler(log_file, maxBytes=int(logsize), backupCount=int(logrotations))
        else:
            handler_csq = logging.StreamHandler(sys.stdout)

        handler_csq.setLevel(9)
        handler_csq.setFormatter(formatter)
        logger_csq = logging.getLogger('cloudstack_queue')
        logger_csq.setLevel(logging.INFO)
        logger_csq.addHandler(handler_csq)
        logger.info("CloudStack Event Queue will be logged on %s" % config['logging']['queue_log_file'])

    # Tag calls logs
    if config['logging']['zabbix_api_log_file']:
        formatter = logging.Formatter('[%(asctime)s]: %(message)s')
        log_file = config['logging']['zabbix_api_log_file']

        if not stdout:
            handler_tags = RotatingFileHandler(log_file, maxBytes=int(logsize), backupCount=int(logrotations))
        else:
            handler_tags = logging.StreamHandler(sys.stdout)

        handler_tags.setLevel(9)
        handler_tags.setFormatter(formatter)
        logger_tags = logging.getLogger('tags')
        logger_tags.setLevel(logging.getLevelName(log_level))
        logger_tags.addHandler(handler_tags)
        logger.info("Outputs from zabbix_api tag calls will be logged on %s" % config['logging']['zabbix_api_log_file'])

    logger.info("Logfiles will have a maximum size of %s bytes, and will be rotated up to %s extra files" %(str(logsize), str(logrotations)))

