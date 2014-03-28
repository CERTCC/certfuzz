'''
Created on Jan 13, 2014

@author: adh
'''
from certfuzz.version import __version__

import logging
from optparse import OptionParser
import os
import platform
import sys

from certfuzz.debuggers import crashwrangler  # @UnusedImport
from certfuzz.debuggers import gdb  # @UnusedImport
from certfuzz.fuzztools import filetools

from certfuzz.campaign.linux import Campaign


def _setup_logging_to_screen(options, logger, fmt):
    # logging to screen
    hdlr = logging.StreamHandler()

    if options.debug:
        level = logging.DEBUG
    elif options.verbose:
        level = logging.INFO
    elif options.quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    add_log_handler(logger, level, hdlr, fmt)


def add_log_handler(log_obj, level, hdlr, formatter):
    hdlr.setLevel(level)
    hdlr.setFormatter(formatter)
    log_obj.addHandler(hdlr)


def _setup_logging_to_file(options, logger, fmt):
    pass


def setup_logging(options):
    logger = logging.getLogger()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s - %(message)s')
    _setup_logging_to_screen(options, logger, fmt)
    _setup_logging_to_file(options, logger, fmt)
    return logger

def parse_options():
    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', help='Turn on debugging output', action='store_true')
    parser.add_option('-c', '--config', dest='cfg', help='Config file location')
    return parser.parse_args()  #@UnusedVariable


def setup_debugging(logger):
    pass


def get_config_file(basedir):
    config_dir = os.path.join(basedir, 'conf.d')

    # check for a platform-specific file
    platform_cfg = 'bff-%s.cfg' % platform.system()

    fullpath_platform_cfg = os.path.join(config_dir, platform_cfg)

    if os.path.exists(fullpath_platform_cfg):
        config_file = fullpath_platform_cfg
    else:
        # default if nothing else is around
        config_file = os.path.join(config_dir, "bff.cfg")

    return config_file


def main():
    # parse command line
    options, args = parse_options()

    # start logging
    logger = setup_logging(options)
    logger.info('Welcome to %s version %s', sys.argv[0], __version__)
    for a in args:
        logger.warning('Ignoring unrecognized argument: %s', a)

    if options.debug:
        setup_debugging(logger)

    scriptpath = os.path.dirname(sys.argv[0])
    logger.info('Scriptpath is %s', scriptpath)

    # Get the cfg file name
    if options.cfg:
        remote_cfg_file = options.cfg
    else:
        remote_cfg_file = get_config_file(scriptpath)

    # die unless the remote config is present
    assert os.path.exists(remote_cfg_file), 'Cannot find remote config file: %s, Please create it or use --config option to specify a different location.' % remote_cfg_file

    # copy remote config to local:
    local_cfg_file = os.path.expanduser('~/bff.cfg')
    filetools.copy_file(remote_cfg_file, local_cfg_file)

    with Campaign(cfg_path=local_cfg_file) as campaign:
        logger.info('Initiating campaign')
        campaign.go()

    logger.info('Campaign complete')


if __name__ == '__main__':
    main()
