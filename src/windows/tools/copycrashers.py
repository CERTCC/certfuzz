'''
Created on Jun 14, 2013

'''

import os
import re
import sys
import shutil
from optparse import OptionParser

regex = {
        'crasher': re.compile('^sf_.+-\w+.\w+$'),
        }


def copycrashers(tld, outputdir):
    # Walk the results directory
    for root, dirs, files in os.walk(tld):
        crash_hash = os.path.basename(root)
        # Only use directories that are hashes
        if "0x" in crash_hash:
            # Check each of the files in the hash directory
            for current_file in files:
                # This gives us the crasher file name
                if regex['crasher'].match(current_file) and 'minimized' not in current_file:
                    crasher_file = os.path.join(root, current_file)
                    print 'Copying %s to %s ...' % (crasher_file, outputdir)
                    shutil.copy(crasher_file, outputdir)
                    
def main():
    # If user doesn't specify a directory to crawl, use "results"
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option('-d', '--dir', 
                      help='directory to look for results in. Default is "results"', 
                      dest='resultsdir', default='results')
    parser.add_option('-o', '--outputdir', dest='outputdir', default='seedfiles',
                      help='Directory to put crashing testcases')
    (options, args) = parser.parse_args()
    outputdir = options.outputdir
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
            
    if not os.path.isdir(outputdir):
        if os.path.isdir('../seedfiles'):
            outputdir = '../seedfiles'
        else:
            print 'cannot find output directory %s' % outputdir
            sys.exit(0)

    copycrashers(tld, outputdir)

if __name__ == '__main__':
    main()

