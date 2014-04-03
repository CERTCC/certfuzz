'''
Created on Jan 13, 2014

@author: adh
'''
import logging
from optparse import OptionParser
import os
import platform
import sys

from certfuzz.debuggers import crashwrangler  # @UnusedImport
from certfuzz.debuggers import gdb  # @UnusedImport
from certfuzz.fuzztools import filetools

from certfuzz.campaign.linux import Campaign
from certfuzz.version import __version__


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
    u = '%prog [options]'
    v = ' '.join(['%prog', 'v%s' % __version__])
    parser = OptionParser(usage=u, version=v)
    parser.add_option('-d', '--debug', dest='debug', action='store_true',
                      help='Enable debug messages to screen and log file (overrides --quiet)')
    parser.add_option('-q', '--quiet', dest='quiet', action='store_true',
                      help='Silence messages to screen (log file will remain at INFO level')
    parser.add_option('-v', '--verbose', dest='verbose', action='store_true',
                      help='Enable verbose logging messages to screen and log file (overrides --quiet)')
    parser.add_option('-c', '--config', dest='configfile', help='Path to config file', metavar='FILE')
# TODO enable these options
#    parser.add_option('-l', '--logfile', dest='logfile', help='Path to log file', metavar='FILE')
#    parser.add_option('-r', '--result-dir', dest='resultdir', help='Path to result directory (overrides config)', metavar='DIR')
    return parser.parse_args()


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
    if options.configfile:
        remote_cfg_file = options.configfile
    else:
        # TODO why are we doing this again?
        remote_cfg_file = get_config_file(scriptpath)

    # die unless the remote config is present
    assert os.path.exists(remote_cfg_file), 'Cannot find remote config file: %s, Please create it or use --config option to specify a different location.' % remote_cfg_file

    with Campaign(cfg_path=options.configfile) as campaign:
        logger.info('Initiating campaign')
        campaign.go()

    logger.info('Campaign complete')


if __name__ == '__main__':
    main()
