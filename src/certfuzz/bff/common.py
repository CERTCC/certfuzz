'''
Created on Apr 3, 2014

@author: adh
'''
import logging
from optparse import OptionParser
import os
import sys

from certfuzz.fuzztools.filetools import mkdir_p

from certfuzz.bff.errors import BFFerror
from certfuzz.version import __version__


logger = logging.getLogger(__name__)


def add_log_handler(log_obj, level, hdlr, formatter):
    hdlr.setLevel(level)
    hdlr.setFormatter(formatter)
    log_obj.addHandler(hdlr)


def setup_debugging():
    logger.debug('Instantiating embedded rpdb2 debugger with password "bff"...')
    try:
        import rpdb2
        rpdb2.start_embedded_debugger("foe", timeout=0.0)
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
        self._parse_options()
        self._process_options()

        self._setup_logging()

        if self.options.debug:
            setup_debugging()

        return self

    def __exit__(self, etype, value, traceback):
        pass

    def _parse_options(self):
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
                          default=self.config_path, metavar='FILE')
        parser.add_option('-l', '--logfile', dest='logfile', default=None,
                          help='Path to log file', metavar='FILE')
        parser.add_option('-r', '--result-dir', dest='resultdir',
                          default=None,
                          help='Path to result directory (overrides config)', metavar='DIR')

        (self.options, self.args) = parser.parse_args()

    def _process_options(self):
        for a in self.args:
            logger.warning('Ignoring unrecognized argument: %s', a)

        # set logfile destination
        if self.options.logfile:
            self.logfile = self.options.logfile
        else:
            self.logfile = self._logfile

        # set log level
        if self.options.debug:
            self.log_level = logging.DEBUG
        elif self.options.verbose:
            self.log_level = logging.INFO
        elif self.options.quiet:
            self.log_level = logging.WARNING

    def _setup_logging(self):
        logdir = os.path.abspath(os.path.dirname(self.logfile))
        mkdir_p(logdir)

        root_logger = logging.getLogger()
        root_logger.setLevel(self.log_level)

        fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s - %(message)s')

        handlers = []
        handlers.append(logging.StreamHandler())
        handlers.append(logging.handlers.RotatingFileHandler(self.logfile,
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
        with self.campaign_class(config_file=self.options.configfile,
                      result_dir=self.options.resultdir,
                      debug=self.options.debug) as campaign:
            logger.info('Starting campaign')
            campaign.go()

        logger.info('Campaign complete')
