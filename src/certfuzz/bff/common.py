'''
Created on Apr 3, 2014

@author: adh
'''
import logging
from logging.handlers import RotatingFileHandler
import os
import sys

from certfuzz.fuzztools.filetools import mkdir_p

from certfuzz.bff.errors import BFFerror
from certfuzz.version import __version__
import argparse


logger = logging.getLogger(__name__)


def add_log_handler(log_obj, level, hdlr, formatter):
    hdlr.setLevel(level)
    hdlr.setFormatter(formatter)
    log_obj.addHandler(hdlr)


def setup_debugging():
    logger.debug('Instantiating embedded rpdb2 debugger with password "bff"...')
    try:
        import rpdb2
        rpdb2.start_embedded_debugger("bff", timeout=0.0)
    except ImportError:
        logger.debug('Skipping import of rpdb2. Is Winpdb installed?')

    logger.debug('Enabling heapy remote monitoring...')
    try:
        from guppy import hpy  # @UnusedImport
        import guppy.heapy.RM  # @UnusedImport
    except ImportError:
        logger.debug('Skipping import of heapy. Is Guppy-PE installed?')


class BFF(object):
    def __init__(self, config_path=None, campaign_class=None):
        self.config_path = config_path
        self.campaign_class = campaign_class

        self._logdir = 'log'
        self._logfile = os.path.abspath(os.path.join(self._logdir, 'bff.log'))
        self.logfile = None
        self.log_level = logging.INFO

    def __enter__(self):
        self._parse_args()
        self._process_args()

        self._setup_logging()

        if self.args.debug:
            setup_debugging()

        return self

    def __exit__(self, etype, value, traceback):
        pass

    def _parse_args(self):
        parser = argparse.ArgumentParser(description='CERT Basic Fuzzing Framework {}'.format(__version__))

        group = parser.add_mutually_exclusive_group()
        group.add_argument('-d', '--debug', dest='debug', action='store_true',
                          help='Set logging to DEBUG and enable additional debuggers if available')
        group.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                          help='Set logging to WARNING level')
        group.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                          help='Set logging to INFO level')

        parser.add_argument('-c', '--config', dest='configfile', type=str, help='Path to config file',
                          default=self.config_path, metavar='FILE')
        parser.add_argument('-l', '--logfile', dest='logfile', type=str, default=self._logfile,
                          help='Path to log file', metavar='FILE')
        parser.add_argument('-r', '--result-dir', dest='resultdir', type=str,
                          default=None,
                          help='Path to result directory (overrides config)', metavar='DIR')

        self.args = parser.parse_args()

    def _process_args(self):
        # set logfile destination
        self.logfile = self.args.logfile

        # set log level
        if self.args.debug:
            self.log_level = logging.DEBUG
        elif self.args.verbose:
            self.log_level = logging.INFO
        elif self.args.quiet:
            self.log_level = logging.WARNING

    def _setup_logging(self):
        logdir = os.path.abspath(os.path.dirname(self.logfile))
        mkdir_p(logdir)

        root_logger = logging.getLogger()
        root_logger.setLevel(self.log_level)

        fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s - %(message)s')

        handlers = []
        handlers.append(logging.StreamHandler())
        handlers.append(RotatingFileHandler(self.logfile,
                        mode='w',
                        maxBytes=1e7,
                        backupCount=5)
                        )

        for handler in handlers:
            add_log_handler(root_logger, self.log_level, handler, fmt)

    def go(self):
        logger.info('Welcome to %s version %s', sys.argv[0], __version__)

        if self.campaign_class is None:
            raise BFFerror('Campaign class is undefined')

        logger.info('Creating campaign')
        with self.campaign_class(config_file=self.args.configfile,
                      result_dir=self.args.resultdir,
                      debug=self.args.debug) as campaign:
            logger.info('Starting campaign')
            campaign.go()

        logger.info('Campaign complete')
