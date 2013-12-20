'''
Created on Oct 23, 2012

@organization: cert.org
'''
import yaml
import os.path
import logging

logger = logging.getLogger(__name__)


def parse_yaml(yaml_file):
    return yaml.load(open(yaml_file, 'r'))

class ConfigError(Exception):
    pass

class Config(object):
    '''
    If you are inheriting this class, add validation methods to self.validations
    to have them run automatically at initialization.
    '''
    def __init__(self, config_file):
        self.file = config_file
        self.config = None
        self.configdate = None

        self.load()
        self._set_derived_options()

        self.validations = []
        self._add_validations()
        self.validate()

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
        pass

    def _add_validations(self):
        pass
