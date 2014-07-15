#!/usr/bin/env python
'''
This script looks for interesting crashes and rate them by potential exploitability
'''
import os
import sys
try:
    from certfuzz.drillresults.common import main
    from certfuzz.drillresults.result_driller_linux import LinuxResultDriller
except ImportError:
    # if we got here, we probably don't have .. in our PYTHONPATH
    mydir = os.path.dirname(os.path.abspath(__file__))
    parentdir = os.path.abspath(os.path.join(mydir, '..'))
    sys.path.append(parentdir)
    from certfuzz.drillresults.common import main
    from certfuzz.drillresults.result_driller_linux import LinuxResultDriller

if __name__ == '__main__':
    main(driller_class=LinuxResultDriller)
