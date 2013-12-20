'''
Created on Jan 14, 2013

@organization: cert.org
'''
import logging
import os

_logger = logging.getLogger(__name__)

def log_formatter():
    log_format = '%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'
    formatter = logging.Formatter(log_format)
    return formatter

def pfunc(logger=None):
    if logger is None:
        logger = _logger

    def real_decorator(function):
        def wrapper(*args, **kwargs):
            params = [str(x) for x in args]
            params.extend(['{}={}'.format(k, v) for k, v in kwargs.iteritems()])
            logger.debug('%d %s(%s)', os.getpid(), function.__name__, ', '.join(params))
            return function(*args, **kwargs)
        return wrapper
    return real_decorator
