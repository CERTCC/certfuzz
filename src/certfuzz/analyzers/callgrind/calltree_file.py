'''
Created on Aug 15, 2011

@organization: cert.org
'''
import re
import logging

from certfuzz.analyzers.callgrind.errors import CallgrindAnnotateNoOutputFileError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class CalltreeFile(object):
    '''
    Annotation File object. Reads in a callgrind annotation file and parses it into a dict (self.coverage)
    '''
    def __init__(self, f):
        self.file = f
        self.lines = None

        self._read()
        self.links = {}
        self.counts = {}

        self.nodes_seen = set()
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

    def print_digraph(self):

        node_id = {}

        print('Digraph G')
        print('{')
        for n_id, node in enumerate(self.nodes_seen):
            short_node = node.split('|')[-1]
            print('\t%d [label="%s"]' % (n_id, short_node))
            node_id[node] = n_id
        for (src, dst) in self.links.items():
            srcnode = node_id[src]
            dstnode = node_id[dst]
            print("\t%s -> %s" % (srcnode, dstnode))
        print('}')

    def process_lines(self):
        caller = None
        called = None
        for l in self.lines:
            logger.debug('Line: %s', l)
            m = re.match('([\d,]+)\s+([*>])\s+(.+)$', l)
            if m:
                (count, typestr, line) = m.groups()
                logger.debug('Count: %s Type: %s Line: %s', count, typestr, line)

                # lib:func (1x) [.so]
                n = re.match('(\S+)(\s+\((\d+)x\))?(\s+\[(.+)\])?', line)
                keyparts = []
                if n:
                    filefunc = n.group(1)
                    # greedy match, separate the string after the last :
                    o = re.match('^(.+):(.+)$', filefunc)
                    if o:
                        (filematch, func) = o.groups()
                    else:
                        logger.debug('Unknown file/function format: %s', filefunc)
                        assert False
                    rpt_count = n.group(3)
                    shared_lib = n.group(5)
#                    logger.debug('Func: %s', func)
                    if rpt_count:
#                        logger.debug('Rpt: %d', int(rpt_count))
                        pass
                    if shared_lib:
#                        logger.debug('ShLib: %s', shared_lib)
                        keyparts.append(shared_lib)
                    keyparts.append(filematch)
                    keyparts.append(func)
                else:
                    logger.debug('Unknown line format: %s', line)
                    continue

                key = '|'.join(keyparts)
                self.nodes_seen.add(key)
                if typestr == "*":
                    caller = key
                    called = None
                elif typestr == ">":
                    called = key

#                print line
                if caller and called:
                    combined_key = ' -> '.join((caller, called))

                    logger.debug('Link: %s -> %s', caller, called)
                    self.links[caller] = called

                    logger.debug('Count: %s %s', combined_key, count)
                    self.counts[combined_key] = count

            else:
                logger.debug('Unmatched: %s', l)
                continue

if __name__ == '__main__':
    from optparse import OptionParser

    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', action='store_true', help='Enable debug messages (overrides --verbose)')
    parser.add_option('', '--outfile', dest='outfile', help='file to write output to')
    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)

    for arg in args:
        a = CalltreeFile(arg)

        a.print_digraph()
