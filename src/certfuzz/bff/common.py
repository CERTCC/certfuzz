'''
Created on Apr 3, 2014

@author: adh
'''
import logging
from optparse import OptionParser
import sys

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

    def __enter__(self):
        self._parse_options()
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

        for a in self.args:
            logger.warning('Ignoring unrecognized argument: %s', a)

    def _setup_logging_to_screen(self, options, fmt):
        # logging to screen
        hdlr = logging.StreamHandler()

        if self.options.debug:
            level = logging.DEBUG
        elif self.options.verbose:
            level = logging.INFO
        elif self.options.quiet:
            level = logging.WARNING
        else:
            level = logging.INFO

        root_logger = logging.getLogger()

        add_log_handler(root_logger, level, hdlr, fmt)

    def _setup_logging_to_file(self, options, logger_, fmt):
        pass
        # TODO make this work
        # logging to file
        # override if option specified
    #    if options.logfile:
    #        logfile = options.logfile
    #    else:
    #        logfile = os.path.join('log', 'bff_log.txt')
    #
    #    hdlr = RotatingFileHandler(logfile, mode='w', maxBytes=1e7, backupCount=5)
    #
    #    hdlr.setFormatter(fmt)
    #    hdlr.setLevel(logging.WARNING)
    #    # override if debug
    #    if options.debug:
    #        hdlr.setLevel(logging.DEBUG)
    #    elif options.verbose:
    #        hdlr.setLevel(logging.INFO)
    #    logger.addHandler(hdlr)

    def _setup_logging(self):
        root_logger = logging.getLogger()

        if self.options.debug:
            root_logger.setLevel(logging.DEBUG)
        else:
            root_logger.setLevel(logging.INFO)

        fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s - %(message)s')
        self._setup_logging_to_screen(self.options, fmt)
        self._setup_logging_to_file(self.options, logger, fmt)

    def go(self):
        logger.info('Welcome to %s version %s', sys.argv[0], __version__)

        if self.campaign_class is None:
            raise BFFerror('Campaign class is undefined')

        with self.campaign_class(config_file=self.options.configfile,
                      result_dir=self.options.resultdir,
                      debug=self.options.debug) as campaign:
            logger.info('Initiating campaign')
            campaign.go()

        logger.info('Campaign complete')

