'''
Created on Jan 12, 2011

@organization: cert.org

'''
import logging
from optparse import OptionParser
import os
import re
import sys
from certfuzz.config.simple_loader import load_and_fix_config


parent_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, parent_path)


logger = logging.getLogger(__name__)
# set default logging level (override with command line options)
logger.setLevel(logging.INFO)

hdlr = logging.StreamHandler(sys.stdout)
logger.addHandler(hdlr)


def _fmt_ln(formats, parts):
    return '\t'.join(fmt % val for (fmt, val) in zip(formats, parts))


def format_header(parts):
    formats = ['%31s', '%12s', '%12s', '%12s', '%12s', '%12s']
    return '#' + _fmt_ln(formats, parts)


def format_line(parts):
    formats = ['%32s', '%12d', '%12d', '%12d', '%12d', '%12d']
    return _fmt_ln(formats, parts)


def record_stats(key, seed_list, counters, first_seeds, last_seeds):
    uniq_seeds = list(set(seed_list))
    logger.debug('seeds=%s', uniq_seeds)
    first_seeds[key] = min(uniq_seeds)
    last_seeds[key] = max(uniq_seeds)
    counters[key] = len(uniq_seeds)
    logger.debug('%s first=%d last=%d count=%d', key, first_seeds[key], last_seeds[key], counters[key])


def get_sort_key(options, counters, bit_hds, byte_hds, first_seeds, last_seeds):
    if options.sort_by_first:
        sort_by = first_seeds
        reverse = False
    elif options.sort_by_last:
        sort_by = last_seeds
        reverse = False
    elif options.sort_by_bits:
        sort_by = bit_hds
        reverse = False
    elif options.sort_by_bytes:
        sort_by = byte_hds
        reverse = False
    else:
        sort_by = counters
        reverse = True
    return sort_by, reverse


def prepare_output(options, counters, bit_hds, byte_hds, first_seeds, last_seeds):
    output_lines = []
    header_line = format_header(('crash_id', 'count', 'first_seed', 'last_seed', 'bitwise_hd', 'bytewise_hd'))
    output_lines.append(header_line)
    sort_by, reverse = get_sort_key(options, counters, bit_hds, byte_hds, first_seeds, last_seeds)
    for dummy, k in sorted([(value, key) for (key, value) in list(sort_by.items())], reverse=reverse):
        parts = [k, counters[k], first_seeds[k], last_seeds[k], bit_hds[k], byte_hds[k]]
        output_lines.append(format_line(parts))
    return output_lines


def parse_cmdline_args():
    parser = OptionParser()
    parser.add_option("-d", "--debug", dest="debug", help="Turn on debugging output", action='store_true', default=False)
    parser.add_option("-F", "--config", dest="cfgfile", help="read config data from FILENAME")
    parser.add_option('', '--first', dest='sort_by_first', help="Sort output by first_seed", action='store_true', default=False)
    parser.add_option('', '--last', dest='sort_by_last', help="Sort output by last_seed", action='store_true', default=False)
    parser.add_option('', '--bits', dest='sort_by_bits', help="Sort output by bitwise_hd", action='store_true', default=False)
    parser.add_option('', '--bytes', dest='sort_by_bytes', help="Sort output by bytewise_hd", action='store_true', default=False)
    options, dummy = parser.parse_args()
    return options


def main():
    options = parse_cmdline_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)

    if options.cfgfile:
        cfg_file = options.cfgfile
    else:
        cfg_file = os.path.join('configs', 'bff.yaml')

    logger.debug('Using config file: %s', cfg_file)
    cfg = load_and_fix_config(cfg_file)

    _campaign_id = cfg['campaign']['id']
    _campaign_id_no_space = re.sub('\s', '_', _campaign_id)

    result_dir = os.path.join(cfg['directories']['results_dir'], _campaign_id_no_space, 'crashers')
    logger.debug('Reading results from %s', result_dir)

    counters = {}
    bit_hds = {}
    byte_hds = {}
    first_seeds = {}
    last_seeds = {}

    if not os.path.isdir(result_dir):
        logger.info('No results dir found at %s', result_dir)
        sys.exit()

    for x in os.listdir(result_dir):
        fullpath = os.path.join(result_dir, x)

        # skip non-directories
        if not os.path.isdir(fullpath):
            logger.debug('Skipping %s - not a dir', fullpath)
            continue

        logger.debug('Entering %s', fullpath)

        crashlog = '%s.log' % x
        fullpath_crashlog = os.path.join(fullpath, crashlog)

        # skip non-existent logs
        if not os.path.isfile(fullpath_crashlog):
            logger.debug('No crash log found at %s', fullpath_crashlog)
            continue

        logger.debug('Processing %s', fullpath_crashlog)
        seed_list = []

        f = open(fullpath_crashlog, 'r')
        try:
            for l in f.readlines():
                m = re.search('at seed=(\d+)', l)
                if m:
                    seed_list.append(int(m.group(1)))
                    logger.debug('%s seed=%s', x, m.group(1))
                    continue

                m = re.match('^bitwise_hd=(\d+)', l)
                if m:
                    bit_hds[x] = int(m.group(1))
                    logger.debug('%s bitwise_hd=%s', x, m.group(1))
                    continue

                m = re.match('^bytewise_hd=(\d+)', l)
                if m:
                    byte_hds[x] = int(m.group(1))
                    logger.debug('%s bytewise_hd=%s', x, m.group(1))
                    continue
        finally:
            f.close()

        if len(seed_list) == 0:
            logger.debug('%s seed_list was empty', x)
            continue

        record_stats(x, seed_list, counters, first_seeds, last_seeds)

    output_lines = prepare_output(options, counters, bit_hds, byte_hds, first_seeds, last_seeds)

    # print your output
    [logger.info(l) for l in output_lines]


if __name__ == '__main__':
    main()

