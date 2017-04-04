import os
import re
import sys
import shutil
from optparse import OptionParser


def copycrashers(tld, outputdir):
    on_osx = False
    if sys.platform == 'darwin':
        # OSX
        debugger_ext = '.cw'
    else:
        # POSIX
        on_osx = True
        debugger_ext = '.gdb'

    # Walk the results directory
    for root, dirs, files in os.walk(tld):
        crash_hash = os.path.basename(root)
        for current_file in files:
            if current_file.endswith(debugger_ext):
                if on_osx and current_file.endswith('.gmalloc.cw'):
                    # Don't mess with any .gmalloc.cw files
                    continue
                crasher_file = os.path.join(
                    root, current_file.replace(debugger_ext, ''))
                if os.path.exists(crasher_file):
                    print('Copying %s to %s ...' % (crasher_file, outputdir))
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
            print('Cannot find resuls directory %s' % tld)
            sys.exit(0)

    if not os.path.isdir(outputdir):
        if os.path.isdir('../seedfiles'):
            outputdir = '../seedfiles'
        else:
            print('cannot find output directory %s' % outputdir)
            sys.exit(0)

    copycrashers(tld, outputdir)

if __name__ == '__main__':
    main()
