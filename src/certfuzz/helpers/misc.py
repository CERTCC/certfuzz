'''
Created on Oct 24, 2012

@organization: cert.org
'''
import logging
import platform
from pprint import pformat, pprint
import random
import string
import os
import sys

logger=logging.getLogger(__name__)

my_os = platform.system()

def import_module_by_name(name):
    '''
    Imports a module at runtime given the pythonic name of the module
    e.g., certfuzz.fuzzers.bytemut
    :param name:
    :param logger:
    '''
    if logger:
        logger.debug('Importing module %s', name)
    __import__(name)
    module = sys.modules[name]
    return module

def fixup_path(path):
    '''
    Expands tildes and returns absolute path transformation of path
    :param path:
    '''
    return os.path.abspath(os.path.expanduser(path))


def quoted(string_to_wrap):
    return '"%s"' % string_to_wrap


def print_dict(d):
    pprint(d)


def random_str(length=1):
    chars = string.ascii_letters + string.digits
    return ''.join([random.choice(chars) for dummy in range(length)])


def bitswap(input_byte):
    bits = [2 ** y for y in range(8)]
    backwards = list(bits)
    backwards.reverse()
    # 1   -> 128
    # 2   -> 64
    # 4   -> 32
    # 8   -> 16
    # 16  -> 8
    # 32  -> 4
    # 64  -> 2
    # 128 -> 1
    output_byte = 0
    for x, y in zip(bits, backwards):
        # if bit x is set in input_byte,
        # set bit y in output_byte
        if input_byte & x:
            output_byte |= y
    return output_byte


def log_object(obj, logger, level=logging.DEBUG):
    for l in pformat(obj.__dict__).splitlines():
        logger.log(level, '%s', l)
