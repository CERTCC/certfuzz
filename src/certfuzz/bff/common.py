'''
Created on Apr 3, 2014

@author: adh
'''
import logging

logger = logging.getLogger(__name__)


def _setup_logging_to_screen(options, fmt):
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


def setup_debugging():
    logger.debug('Instantiating embedded rpdb2 debugger with password "bff"...')
    try:
        import rpdb2
        rpdb2.start_embedded_debugger("foe", timeout=0.0)
    except ImportError:
        logger.debug('Error importing rpdb2. Is Winpdb installed?')

    logger.debug('Enabling heapy remote monitoring...')
    try:
        from guppy import hpy  # @UnusedImport
        import guppy.heapy.RM  # @UnusedImport
    except ImportError:
        logger.debug('Error importing heapy. Is Guppy-PE installed?')
