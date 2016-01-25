'''
Created on Oct 23, 2012

@organization: cert.org
'''
import logging
import os.path

import yaml
from certfuzz.config.errors import ConfigError
from string import Template
from certfuzz.helpers.misc import quoted
import re


logger = logging.getLogger(__name__)


def parse_yaml(yaml_file):
    with open(yaml_file, 'r') as f:
        stuff = yaml.load(f)
    return stuff


class ConfigBase(object):
    '''
    If you are inheriting this class, add validation methods to self.validations
    to have them run automatically at initialization.
    '''
    def __init__(self, config_file):
        self.file = config_file
        self.config = None
        self.configdate = None
        self.validations = []

    def __enter__(self):
        self.load()
        self._set_derived_options()
        self._add_validations()
        self.validate()
        return self

    def __exit__(self, etype, value, traceback):
        pass

    def load(self):
        logger.debug('loading config from %s', self.file)
        try:
            self.config = parse_yaml(self.file)
            self.configdate = os.path.getmtime(self.file)
        except IOError:
            pass

        if self.config:
            self.__dict__.update(self.config)

    def validate(self):
        for validation in self.validations:
            validation()

    def _set_derived_options(self):
        if self.config is None:
            raise ConfigError('No config found (or config file empty?)')
        # interpolate program name
        # add quotes around $SEEDFILE
        t = Template(self.config['target']['cmdline_template'])
        self.config['target']['cmdline_template'] = t.safe_substitute(PROGRAM=quoted(self.config['target']['program']),
                          SEEDFILE=quoted('$SEEDFILE'))
 
        campaign_id = re.sub('\s+', '_', self.config['campaign']['id'])
        self.config['campaign']['id'] = campaign_id

 

    def _add_validations(self):
        pass
