#!/usr/bin/env python
'''
This script looks for interesting crashes and rate them by potential exploitability
'''
import os
import sys
import platform

try:
    from certfuzz.drillresults.common import main
    from certfuzz.drillresults.result_driller_linux import LinuxResultDriller
    from certfuzz.drillresults.result_driller_darwin import DarwinResultDriller
except ImportError:
    # if we got here, we probably don't have .. in our PYTHONPATH
    mydir = os.path.dirname(os.path.abspath(__file__))
    parentdir = os.path.abspath(os.path.join(mydir, '..'))
    sys.path.append(parentdir)
    from certfuzz.drillresults.common import main
    from certfuzz.drillresults.result_driller_linux import LinuxResultDriller
    from certfuzz.drillresults.result_driller_darwin import DarwinResultDriller

if __name__ == '__main__':
    plat = platform.system()
    if plat == 'Darwin':
        main(driller_class=DarwinResultDriller)
    else:
        main(driller_class=LinuxResultDriller)
