#!/usr/bin/env python
'''
Created on Aug 16, 2011

@organization: cert.org
'''
import os
import sys
import logging
from optparse import OptionParser

parent_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, parent_path)

from certfuzz.fuzztools.similarity_matrix import SimilarityMatrix
from certfuzz.fuzztools.similarity_matrix import SimilarityMatrixError
from certfuzz.fuzztools.distance_matrix import DistanceMatrixError

logger = logging.getLogger()
logger.setLevel(logging.WARNING)

if __name__ == '__main__':

    parser = OptionParser(usage='%prog [options] <dir1> ... <dirN>')
    parser.add_option('', '--debug', dest='debug', action='store_true', help='Enable debug messages (overrides --verbose)')
    parser.add_option('', '--verbose', dest='verbose', action='store_true', help='Enable verbose messages')
    parser.add_option('', '--outfile', dest='outfile', help='file to write output to')
    parser.add_option('', '--precision', dest='precision', help='Number of digits to print in similarity')
    parser.add_option('', '--style', dest='style', help='Either "list" or "tree"')

    (options, args) = parser.parse_args()

    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    if options.verbose:
        logger.setLevel(logging.INFO)
    if options.debug:
        logger.setLevel(logging.DEBUG)

    if not len(args):
        print "You must specify at least one dir to crawl.\n"
        parser.print_help()
        exit(-1)
    else:
        logger.debug('Args: %s', args)

    try:
        sim = SimilarityMatrix(args)
    except SimilarityMatrixError, e:
        print 'Error:', e
        exit(-1)

    if options.precision:
        sim.precision = options.precision

    if not options.style or options.style == 'list':
        # Print the results
        if options.outfile:
            target = options.outfile
        else:
            # default goes to sys.stdout
            target = None

        sim.print_to(target)

    elif options.style == 'tree':
        from certfuzz.fuzztools.distance_matrix import DistanceMatrix

        if options.outfile:
            target = options.outfile
        else:
            target = 'cluster.png'

        dm = DistanceMatrix(sim.sim)
        try:
            dm.to_image(target)
        except DistanceMatrixError, e:
            print "PIL not installed, skipping image creation."
    else:
        # it's something other than None, list, or tree
        print "The only allowed values for --style are 'list' and 'tree': %s" % options.style
        parser.print_help()
        exit(-1)
