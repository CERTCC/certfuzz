'''
Created on Jan 13, 2016

@author: adh
'''
import logging
import yaml
import os

logger = logging.getLogger(__name__)


def load_config(yaml_file):
    with open(yaml_file, 'rb') as f:
        cfg = yaml.load(f)

    # yaml.load returns None if the file is empty. We need to raise an error
    from errors import ConfigError
    if cfg is None:
        raise(ConfigError,'Config file was empty')
    # add the file timestamp so we can tell if it changes later
    cfg['config_timestamp'] = os.path.getmtime(yaml_file)

    return cfg
