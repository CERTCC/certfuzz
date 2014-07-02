#!/usr/bin/env python
'''
This script looks for interesting crashes and rate them by potential exploitability
'''
import os
import sys
try:
    from certfuzz.drillresults.drillresults_linux import main
except ImportError:
    # if we got here, we probably don't have .. in our PYTHONPATH
    mydir = os.path.dirname(os.path.abspath(__file__))
    parentdir = os.path.abspath(os.path.join(mydir, '..'))
    sys.path.append(parentdir)
    from certfuzz.drillresults.drillresults_linux import main

if __name__ == '__main__':
    main()
