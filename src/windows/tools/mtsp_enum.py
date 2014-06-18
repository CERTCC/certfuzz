'''
Created on Mar 8, 2013

@organization: cert.org
'''
import os
import sys
try:
    from certfuzz.tools.common.mtsp_enum import main
except ImportError:
    # if we got here, we probably don't have .. in our PYTHONPATH
    mydir = os.path.dirname(os.path.abspath(__file__))
    parentdir = os.path.abspath(os.path.join(mydir, '..'))
    sys.path.append(parentdir)
    from certfuzz.tools.common.mtsp_enum import main

if __name__ == '__main__':
    main()
