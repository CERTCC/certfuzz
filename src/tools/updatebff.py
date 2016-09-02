#!/usr/bin/env python
'''
Created on September 1, 2016

@organization: cert.org
'''
import os
import sys
try:
    from certfuzz.tools.common.updatebff import main
except ImportError:
    # if we got here, we probably don't have .. in our PYTHONPATH
    mydir = os.path.dirname(os.path.abspath(__file__))
    parentdir = os.path.abspath(os.path.join(mydir, '..'))
    sys.path.append(parentdir)
    try:
        from certfuzz.tools.common.updatebff import main
    except ImportError:
        # certfuzz likely downgraded to pre-2.8 version
        raise Exception('%s requires BFF 2.8 or later' % __file__)

if __name__ == '__main__':
    main()
