'''
Created on Jun 21, 2013

@organization: cert.org
'''

import logging
import os
import shutil
import yaml
import argparse
from certfuzz.android.api.log_helper import log_formatter

logger = logging.getLogger()
hdlr = logging.StreamHandler()
hdlr.setFormatter(log_formatter())
logger.addHandler(hdlr)


def main():
    parser = argparse.ArgumentParser(description='Create a configuration file with the default options')
    parser.add_argument('--force', '-f',
                        help='Overwrite the config file if it already exists',
                        action='store_true', default=False)
    parser.add_argument('--directory', '--dir', '-d',
                        help='The directory in which to store the config file',
                        default='config')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--debug', help='', action='store_true')
    group.add_argument('--verbose', help='', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    populate_config_dir(force=args.force, directory=args.directory)


def populate_config_dir(force=False, directory='config'):

    prefix = 'android'
    config_files = ['certfuzz/android/config.yaml']

    # TODO should there be some check in place to ensure that this is running
    # from the correct working directory? (i.e. ~/android/src/).  Otherwise
    # it will break when trying to find the config files.

    if not os.path.exists(directory):
        os.mkdir(directory)

    for f in config_files:
        cp_path = '%s/%s_%s' % (directory, prefix, os.path.basename(f))
        config_exists = os.path.exists(cp_path)

        if config_exists:
            logger.warning('%s already exists' % cp_path)
            if not force:
                logger.warning('Please specify --overwrite if you wish to overwrite %s' % cp_path)

        if force or not config_exists:
            logger.info('Copying %s to %s' % (f, cp_path))
            shutil.copy(f, cp_path)


def load_config(cfg_file):

    if os.path.exists(cfg_file):
        logging.info('Loading config: %s' % cfg_file)
        return yaml.safe_load(open(cfg_file, 'r'))
    else:
        logger.error('Could not find config: %s' % cfg_file)
        return None

if __name__ == "__main__":
    main()
