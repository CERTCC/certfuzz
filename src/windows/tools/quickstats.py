'''
Created on Jun 14, 2013

'''

import os
import sys
from optparse import OptionParser

explevels = ['EXPLOITABLE', 'PROBABLY_EXPLOITABLE',
             'PROBABLY_NOT_EXPLOITABLE', 'UNKNOWN', 'HEISENBUG']


def countcrashers(tld):
    totalcrashers = 0
    # Walk the results directory
    for root, dirs, files in os.walk(tld):
        curdir = os.path.basename(root)
        for explevel in explevels:
            if curdir == explevel:
                explevelcount = len([hash for hash in os.listdir(root) if '0x' in hash])
                totalcrashers = totalcrashers + explevelcount
                print '%s: %s' % (explevel, explevelcount)
    print 'Total: %s' % totalcrashers
            
                                
def main():
    # If user doesn't specify a directory to crawl, use "results"
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option('-d', '--dir', 
                      help='directory to look for results in. Default is "results"', 
                      dest='resultsdir', default='results')
    (options, args) = parser.parse_args()
    tld = options.resultsdir
    if not os.path.isdir(tld):
        if os.path.isdir('../results'):
            tld = '../results'
        elif os.path.isdir('crashers'):
            # Probably using FOE 1.0, which defaults to "crashers" for output
            tld = 'crashers'
        else:
            print 'Cannot find resuls directory %s' % tld
            sys.exit(0)
            
    countcrashers(tld)

if __name__ == '__main__':
    main()

