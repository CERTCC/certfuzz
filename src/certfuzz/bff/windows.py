'''
Created on Jan 13, 2014

@author: adh
'''

import logging
from logging.handlers import RotatingFileHandler
from optparse import OptionParser
import os
import sys

from certfuzz.campaign.campaign_windows import WindowsCampaign as Campaign

from certfuzz.bff.common import _setup_logging_to_screen, setup_debugging
from certfuzz.version import __version__


def _setup_logging_to_file(options, logger, fmt):
    # logging to file
    # override if option specified
    if options.logfile:
        logfile = options.logfile
    else:
        logfile = os.path.join('log', 'foe2log.txt')

    hdlr = RotatingFileHandler(logfile, mode='w', maxBytes=1e7, backupCount=5)

    hdlr.setFormatter(fmt)
    hdlr.setLevel(logging.WARNING)
    # override if debug
    if options.debug:
        hdlr.setLevel(logging.DEBUG)
    elif options.verbose:
        hdlr.setLevel(logging.INFO)
    logger.addHandler(hdlr)


def setup_logging(options):
    logger = logging.getLogger()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s - %(message)s')
    _setup_logging_to_screen(options, fmt)
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
    parser.add_option('-c', '--config', dest='configfile', help='Path to config file',
                      default='configs/foe.yaml', metavar='FILE')
    parser.add_option('-l', '--logfile', dest='logfile', help='Path to log file', metavar='FILE')
    parser.add_option('-r', '--result-dir', dest='resultdir', help='Path to result directory (overrides config)', metavar='DIR')

    return parser.parse_args()


def main():
    # parse command line
    options, args = parse_options()

    # start logging
    logger = setup_logging(options)
    logger.info('Welcome to %s version %s', sys.argv[0], __version__)
    for a in args:
        logger.warning('Ignoring unrecognized argument: %s', a)

    if options.debug:
        setup_debugging()

    with Campaign(config_file=options.configfile, result_dir=options.resultdir, debug=options.debug) as campaign:
        logger.info('Initiating campaign')
        campaign.go()

    logger.info('Campaign complete')
