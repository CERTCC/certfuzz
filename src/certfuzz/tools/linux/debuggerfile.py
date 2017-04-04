'''
Created on Oct 15, 2012

@organization: cert.org
'''

import logging
from optparse import OptionParser
import sys
import os

mydir = os.path.dirname(os.path.abspath(__file__))
parentdir = os.path.abspath(os.path.join(mydir, '..'))
sys.path.append(parentdir)

from certfuzz.debuggers.output_parsers.gdbfile import GDBfile
from certfuzz.debuggers.output_parsers.cwfile import CWfile

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


def main():
    logger = logging.getLogger()
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', action='store_true', help='Enable debug messages (overrides --verbose)')
    parser.add_option('', '--verbose', dest='verbose', action='store_true', help='Enable verbose messages')
    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    elif options.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    for f in args:
        debugger = os.path.splitext(f)[1]
        if debugger == '.gdb':
            g = GDBfile(f)
        elif debugger == '.cw':
            g = CWfile(f)
        elif debugger == '':
            parser.error('No file suffix found, but \'.gdb\' or \'.cw\' expected')
        else:
            parser.error('Unknown file suffix \'%s\' found, but \'.gdb\' or \'.cw\' expected' % debugger)
        print('Signature=%s' % g.get_testcase_signature(5))
        if g.registers_hex.get(g.pc_name):
            print('PC=%s' % g.registers_hex[g.pc_name])


if __name__ == '__main__':
    main()
