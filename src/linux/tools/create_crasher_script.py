#!/usr/bin/env python
'''
Created on Jan 13, 2011

@organization: cert.org

'''

from optparse import OptionParser
import logging
import sys
import os
import re

parent_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, parent_path)

from certfuzz.campaign.config.bff_config import read_config_options

logger = logging.getLogger(__name__)
# set default logging level (override with command line options)
logger.setLevel(logging.INFO)
stdout_hdlr = logging.StreamHandler(sys.stdout)
stderr_hdlr = logging.StreamHandler(sys.stderr)
stderr_hdlr.setLevel(logging.WARNING)

logger.addHandler(stdout_hdlr)
logger.addHandler(stderr_hdlr)

def parse_options():
    usage = "usage: %prog [options] <crash_id>"

    parser = OptionParser(usage)
    parser.add_option("-d", "--debug", dest="debug", help="Turn on debugging output", action='store_true', default=False)
    parser.add_option("-F", "--config", dest="cfgfile", help="read config data from CFGFILE")
    parser.add_option("-o", '--outfile', dest='outfile', help="write script to OUTFILE instead of stdout")
    parser.add_option("", "--force", dest="force", help="Force overwrite of existing OUTFILE", action='store_true', default=False)
    parser.add_option('', '--destination', dest='dest', help="Replace output location in script with DEST")

    options, args = parser.parse_args()
    if not len(args):
        parser.print_help()
        parser.error("Please specify a crash_id")
    return options, args

if __name__ == '__main__':
    options, args = parse_options()

    if options.debug:
        logger.setLevel(logging.DEBUG)

    file_logger = False
    if options.outfile:
        file_logger = logging.getLogger('outfile')
        file_logger.setLevel(logging.INFO)
        if os.path.exists(options.outfile) and not options.force:
            logging.warning('%s exists, use --force to overwrite', options.outfile)
            sys.exit()
        hdlr = logging.FileHandler(options.outfile, 'w')
        fmt = logging.Formatter('%(message)s')
        hdlr.setFormatter(fmt)
        hdlr.setLevel(logging.INFO)
        file_logger.addHandler(hdlr)
        # since we're logging to a file, we can suppress output to stdout
        # but we still want to keep warnings
        if not options.debug:
            logger.removeHandler(stdout_hdlr)

    if options.cfgfile:
        cfg_file = options.cfgfile
    else:
        cfg_file = os.path.join(parent_path, 'conf.d', 'bff.cfg')

    logger.debug('Using config file: %s', cfg_file)
    cfg = read_config_options(cfg_file)

    result_dir = cfg.crashers_dir
    logger.debug('Reading results from %s', result_dir)

    for crash_id in args:
        logger.debug('Crash_id=%s', crash_id)
        crash_dir = os.path.join(result_dir, crash_id)
        if not os.path.isdir(crash_dir):
            logger.debug('%s is not a dir', crash_dir)
            continue

        logger.debug('Looking for crash log in %s', crash_dir)
        log = os.path.join(crash_dir, crash_id + '.log')
        if not os.path.exists(log):
            logger.warning('No log found at %s', log)
            continue

        logger.debug('Found log at %s', log)

        f = open(log, 'r')
        try:
            for l in f.readlines():
                m = re.match('^Command:\s+(.+)$', l)
                if not m:
                    continue

                cmdline = m.group(1)

                if options.dest:
                    (cmd, dst) = [x.strip() for x in cmdline.split('>')]
                    filename = os.path.basename(dst)
                    logger.debug(filename)
                    new_dst = os.path.join(options.dest, filename)
                    logger.debug(new_dst)
                    cmdline = ' > '.join((cmd, new_dst))

                if file_logger:
                    file_logger.info(cmdline)
                else:
                    logger.info(cmdline)
        finally:
            f.close()
