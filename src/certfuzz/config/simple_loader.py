'''
Created on Jan 13, 2016

@author: adh
'''
import logging
import yaml
import os
from .errors import ConfigError
from certfuzz.helpers.misc import fixup_path, quoted
from string import Template
from copy import deepcopy

logger = logging.getLogger(__name__)


def load_config(yaml_file):
    '''
    Reads config from yaml_file, returns dict
    :param yaml_file: path to a yaml file containing the configuration
    '''
    with open(yaml_file, 'rb') as f:
        cfg = yaml.load(f)

    # yaml.load returns None if the file is empty. We need to raise an error
    if cfg is None:
        raise ConfigError

    # add the file timestamp so we can tell if it changes later
    cfg['config_timestamp'] = os.path.getmtime(yaml_file)

    return cfg

def fixup_config(cfg):
    '''
    Substitutes program name into command line template
    returns modified dict
    '''
    # copy the dictionary
    cfgdict = deepcopy(cfg)
    # fix target program path
    cfgdict['target']['program'] = fixup_path(cfgdict['target']['program'])

    quoted_prg = quoted(cfgdict['target']['program'])
    quoted_sf = quoted('$SEEDFILE')
    t = Template(cfgdict['target']['cmdline_template'])
    intermediate_t = t.safe_substitute(PROGRAM=quoted_prg, SEEDFILE=quoted_sf)
    cfgdict['target']['cmdline_template'] = Template(intermediate_t)

    for k, v in cfgdict['directories'].items():
        cfgdict['directories'][k] = fixup_path(v)

    if 'analyzer' not in cfgdict: cfgdict['analyzer'] = {}

    return cfgdict

def load_and_fix_config(yaml_file):
    return fixup_config(load_config(yaml_file))
