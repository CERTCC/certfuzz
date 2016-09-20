#!/usr/bin/env python
'''
Created on Jan 13, 2011

@organization: cert.org
'''
import os
import sys
try:
    from linux_minimizer_plot import main
except ImportError:
    # if we got here, we probably don't have .. in our PYTHONPATH
    mydir = os.path.dirname(os.path.abspath(__file__))
    parentdir = os.path.abspath(os.path.join(mydir, '..'))
    sys.path.append(parentdir)
    from linux_minimizer_plot import main

if __name__ == '__main__':
    main()
