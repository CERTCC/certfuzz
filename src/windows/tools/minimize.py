'''
Created on Apr 9, 2012

@organization: cert.org
'''
import os
import sys
try:
    from certfuzz.tools.windows.minimize import main
except ImportError:
    # if we got here, we probably don't have .. in our PYTHONPATH
    mydir = os.path.dirname(os.path.abspath(__file__))
    parentdir = os.path.abspath(os.path.join(mydir, '..'))
    sys.path.append(parentdir)
    from certfuzz.tools.windows.minimize import main

if __name__ == '__main__':
    main()
