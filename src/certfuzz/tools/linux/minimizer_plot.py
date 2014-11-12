'''
Created on Jan 13, 2011

@organization: cert.org
'''

import logging
from optparse import OptionParser
import os
import re
import sys

from certfuzz.config.config_linux import LinuxConfig
import matplotlib.pyplot as plt


parent_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, parent_path)

logger = logging.getLogger(__name__)
# set default logging level (override with command line options)
logger.setLevel(logging.INFO)

hdlr = logging.StreamHandler(sys.stdout)
logger.addHandler(hdlr)


def parse_options():
    usage = "usage: %prog [options] <crash_id>"
    parser = OptionParser(usage)
    parser.add_option("-d", "--debug", dest="debug", help="Turn on debugging output (overrides --verbose)", action='store_true', default=False)
    parser.add_option("-v", "--verbose", dest="verbose", help="Turn on verbose output", action='store_true', default=False)
    parser.add_option('', '--dir', dest='dir', help='Specify crasher parent dir')
    parser.add_option("-F", "--config", dest="cfgfile", help="read config data from CFGFILE", metavar='CFGFILE')
    parser.add_option('', '--ylin', dest='linear_y', help="use linear scale on Y axis (default is logarithmic)", action='store_true', default=False)
    parser.add_option('', '--xlog', dest='log_x', help="use log scale on X axis (default is linear)", action='store_true', default=False)
    parser.add_option('', '--no-crash-id', dest='include_crash_id', help='suppress inclusion of crash_id in chart title', action='store_false', default=True)
    parser.add_option('', '--infile', dest="infile", help="read minimizer log from FILE", metavar='FILE')
    options, args = parser.parse_args()
    if not len(args):
        parser.print_help()
        parser.error("Please specify a crash md5 to plot")
    return options, args


def plot(options, crash_id, log):
    logfile = LogFile(log)
#    results = logfile.results
    starts = []
    mins = []
    targets = []
    currents = []
    for item in logfile.results:
        [x.append(y) for x, y in zip((starts, mins, targets, currents), item)]

    logger.debug("Got data to plot:")
    [logger.debug('%s', str(x)) for x in (starts, mins, targets, currents)]
    fig = plt.figure(figsize=(8, 8))
    ax = fig.add_subplot(1, 1, 1)
    if not options.linear_y:
        logger.info('Setting log scale on y-axis')
        ax.set_yscale('log')
    if options.log_x:
        logger.info('Setting linear scale on x-axis')
        ax.set_xscale('log')
    logger.info('Building plot')
    plt.xlabel('Iteration')
    plt.ylabel('Hamming Distance')
    title = 'Crash Minimization'
# prepend the crash_id unless the user told us not to
    if options.include_crash_id:
        title = '\n'.join((crash_id, title))
    plt.title(title)
    plt.plot(starts, label='start_hd')
    plt.plot(mins, label='min_found')
    plt.plot(targets, label='target_guess')
    plt.plot(currents, label='current_try')
    logger.debug('Add legend to plot')
    plt.legend()
    logger.debug('Draw the plot')
    plt.show()


class Line():
    def __init__(self, line):
        self.line = line.strip()
        self.value = False
        self._process()

    def _process(self):
        m = re.match('^start=(\d+)\s+min=(\d+)\s+target_guess=(\d+)\s+curr=(\d+)', self.line)
        if not m:
            return

        (start, minimum, target, current) = (int(x) for x in (m.group(1), m.group(2), m.group(3), m.group(4)))
        logger.debug('start: %d', start)
        logger.debug('min: %d', minimum)
        logger.debug('target: %d', target)
        logger.debug('current: %d', current)
        self.value = (start, minimum, target, current)


class LogFile():
    def __init__(self, logfile):
        self.file = logfile
        self.results = []
        self.uniqresults = []
        self.results_read = False
        self._process()
        logger.debug('Created LogFile object for %s', self.file)

    def _process(self):
        if self.results_read:
            return self.results

        f = open(self.file, 'r')
        try:
            for l in f.readlines():
                result = Line(l).value
                if result:
                    self.results.append(result)
            self.results_read = True
        finally:
            f.close()

    def unique_results(self):
        if self.uniqresults:
            return self.uniqresults

        self.uniqresults = list(set(self.results))
        return self.uniqresults


def main():
    options, args = parse_options()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    elif options.verbose:
        logger.setLevel(logging.INFO)

    if options.cfgfile:
        cfg_file = options.cfgfile
    else:
        cfg_file = os.path.join(parent_path, 'conf.d', 'bff.cfg')

    if options.dir:
        result_dir = options.dir
    else:
        logger.info('Using config file: %s', cfg_file)
        cfg = LinuxConfig(cfg_file)
        with cfg:
            pass

        result_dir = cfg.crashers_dir
        logger.info('Reading results from %s', result_dir)

    log = None
    crash_id = None
    if len(args):
        crash_id = args.pop(0)
        logger.debug('Crash_id=%s', crash_id)
        crashdir = os.path.join(result_dir, crash_id)
        if not os.path.isdir(crashdir):
            logger.debug('%s is not a dir', crashdir)
            raise

        logger.debug('Looking for minimizer log in %s', crashdir)
        log = os.path.join(crashdir, 'minimizer_log.txt')
    elif options.infile:
        crash_id = os.path.basename(options.infile)
        log = options.infile

    if not os.path.exists(log):
        logger.warning('No minimizer log found at %s', log)
        raise
    logger.info('Found log at %s', log)
    plot(options, crash_id, log)

    logger.info('All done. Bye.')


if __name__ == '__main__':
    main()
