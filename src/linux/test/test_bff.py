'''
Created on Apr 11, 2011

@organization: cert.org
'''
import time
import tempfile
import os
import shutil
import unittest
import sys

mydir = os.path.dirname(os.path.abspath(__file__))
parentdir = os.path.abspath(os.path.join(mydir, '..'))
sys.path.append(parentdir)

import certfuzz.bff.linux as bff

class Mock(object):
    def __init__(self):
        self.is_crash = True
        self.is_assert_fail = False
        self.registers_hex = {'eip': '0xdeadbeef'}
        self.debugger_missed_stack_corruption = False
        self.total_stack_corruption = False

    def go(self):
        return Mock()

    def get_crash_signature(self, dummy):
        return os.urandom(10)

class Test(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass
#    def test_get_rate(self):
#        bff.SEED_TS = Mock()
#        bff.SEED_TS.since_start = lambda: 1.0
#        for i in range(100):
#            self.assertEqual(float(i / 1.0), bff.get_rate(i))
#
#    def test_get_uniq_logger(self):
#        logfile = tempfile.mktemp()
#        ulog = bff.get_uniq_logger(logfile)
#        self.assertEqual('Logger', ulog.__class__.__name__)
#        self.assertEqual(0, os.path.getsize(logfile))
#        msg = 'foo'
#        ulog.warning(msg)
#        # length is msg + a carriage return
#        self.assertEqual(len(msg) + 1, os.path.getsize(logfile))
#        os.remove(logfile)
#        self.assertFalse(os.path.exists(logfile))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.test_load_obj_from_file']
    unittest.main()
