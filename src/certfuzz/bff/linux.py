'''
Created on Jan 13, 2014

@author: adh
'''
__version__ = '2.8'

import logging
from logging.handlers import RotatingFileHandler
from optparse import OptionParser
import os
import platform
import sys

from ..debuggers import crashwrangler  # @UnusedImport
from ..debuggers import gdb  # @UnusedImport
from ..file_handlers.seedfile_set import SeedfileSet
from ..file_handlers.tmp_reaper import TmpReaper
from ..fuzztools import bff_helper as z, filetools, performance
from certfuzz.campaign.linux import Campaign


DEBUG = True

SEED_INTERVAL = 500

#SEED_TS = performance.TimeStamper()
#START_SEED = 0

logger = logging.getLogger()
logger.name = 'bff'
logger.setLevel(0)


#def get_rate(current_seed):
#    seeds = current_seed - START_SEED
#    rate = seeds / SEED_TS.since_start()
#    return rate


def get_uniq_logger(logfile):
    l = logging.getLogger('uniq_crash')
    if len(l.handlers) == 0:
        hdlr = logging.FileHandler(logfile)
        l.addHandler(hdlr)
    return l



def setup_logging_to_console(log_obj, level):
    hdlr = logging.StreamHandler()
    formatter = logging.Formatter('%(name)s %(message)s')
    add_log_handler(log_obj, level, hdlr, formatter)


def setup_logfile(logdir, log_basename='bff.log', level=logging.DEBUG,
                  max_bytes=1e8, backup_count=5):
    '''
    Creates a log file in <logdir>/<log_basename> at level <level>
    @param logdir: the directory where the log file should reside
    @param log_basename: the basename of the logfile (defaults to 'bff_log.txt')
    @param level: the logging level (defaults to logging.DEBUG)
    '''
    filetools.make_directories(logdir)
    logfile = os.path.join(logdir, log_basename)
    handler = RotatingFileHandler(logfile, maxBytes=max_bytes, backupCount=backup_count)
    formatter = logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s")
    add_log_handler(logger, level, handler, formatter)
    logger.info('Logging %s at %s', logging.getLevelName(level), logfile)


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


def add_log_handler(log_obj, level, hdlr, formatter):
    hdlr.setLevel(level)
    hdlr.setFormatter(formatter)
    log_obj.addHandler(hdlr)


def main():
#    global START_SEED
#    hashes = []

#    # give up if we don't have a debugger
#    debuggers.verify_supported_platform()

    setup_logging_to_console(logger, logging.INFO)
    setup_logfile()
    logger.info("Welcome to BFF!")

    scriptpath = os.path.dirname(sys.argv[0])
    logger.info('Scriptpath is %s', scriptpath)

    # parse command line options
    logger.info('Parsing command line options')
    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', help='Turn on debugging output', action='store_true')
    parser.add_option('-c', '--config', dest='cfg', help='Config file location')
    (options, args) = parser.parse_args()  #@UnusedVariable

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
        campaign.go()


if __name__ == '__main__':
    main()
