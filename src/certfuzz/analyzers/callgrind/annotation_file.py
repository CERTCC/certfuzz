'''
Created on Aug 15, 2011

@organization: cert.org
'''
import re
import logging
from certfuzz.analyzers.callgrind.errors import CallgrindAnnotateNoOutputFileError


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class AnnotationFile(object):
    '''
    Annotation File object. Reads in a callgrind annotation file and parses it into a dict (self.coverage)
    '''
    def __init__(self, f):
        self.file = f
        self.lines = None

        self._read()
        self.coverage = {}
        self.process_lines()

    def _read(self):
        try:
            fd = open(self.file, 'r')
            self.lines = [l.strip() for l in fd.readlines()]
        except:
            raise CallgrindAnnotateNoOutputFileError(self.file)

    def print_lines(self):
        for l in self.lines:
            print(l)

    def print_coverage(self):
        for (k, v) in self.coverage.items():
            print(k, v)

    def process_coverage_line(self, line):
        m = re.match('([\d,]+)\s+([^:]+):(.+)\s+\[([^]]*)\]', line)
        if m:
            count = int(m.group(1).replace(',', ''))
            filematch = m.group(2)
            func = m.group(3)
            lib = ''
            if m.group(4):
                lib = m.group(4)
            logger.debug("COUNT=%d FILE=%s FUNC=%s LIB=%s", count, filematch, func, lib)
            key = ':'.join((lib, filematch, func))
            self.coverage[key] = count
        else:
            logger.debug("Unprocessed: %s" % line)

    def process_lines(self):
        for line in self.lines:
            self.process_coverage_line(line)

if __name__ == '__main__':
    from optparse import OptionParser

    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', action='store_true', help='Enable debug messages (overrides --verbose)')
    parser.add_option('', '--outfile', dest='outfile', help='file to write output to')
    (options, args) = parser.parse_args()

    for arg in args:
        a = AnnotationFile(arg)
        print(a.__dict__)
