import os
import tempfile
from certfuzz.fuzztools.zzuflog import ZzufLog
'''
Created on Apr 8, 2011

@organization: cert.org
'''

import unittest

class Test(unittest.TestCase):
    def delete_file(self, f):
        if os.path.exists(f):
            os.remove(f)
        self.assertFalse(os.path.exists(f))

    def tearDown(self):
        self.delete_file(self.infile)
        self.delete_file(self.outfile)

    def setUp(self):
        (fd1, f1) = tempfile.mkstemp(text=True)
        os.close(fd1)
        self.infile = f1

        (fd2, f2) = tempfile.mkstemp(text=True)
        os.close(fd2)
        self.outfile = f2

        self.log = ZzufLog(self.infile, self.outfile)

    def test_get_last_line(self):
        open(self.infile, 'w')
        self.assertEqual(self.log._get_last_line(), '')

        (fd, f) = tempfile.mkstemp(text=True)
        os.write(fd, "firstline\n")
        os.write(fd, "secondline\n")
        os.write(fd, "thirdline\n")
        os.close(fd)

        log = ZzufLog(f, self.outfile)
        # log.line gets the result of _get_last_line before the infile is wiped out
        self.assertEqual(log.line, 'thirdline')
        self.delete_file(f)

    def test_set_exitcode(self):
        self.log.result = "blah"
        self.log._set_exitcode()
        self.assertEqual(self.log.exitcode, '')

        self.log.result = "exit 1701"
        self.log._set_exitcode()
        self.assertEqual(self.log.exitcode, 1701)

    def test_set_signal(self):
        self.log.result = "blah"
        self.log._set_signal()
        self.assertEqual(self.log.signal, '')

        self.log.result = "signal 17938"
        self.log._set_signal()
        self.assertEqual(self.log.signal, '17938')

    def test_parse_line(self):
        self.log.line = "blah"
        self.assertEqual(self.log._parse_line(), (False, False, ''))
        self.log.line = "zzuf[s=99,r=foo]: Welcome to Jurassic Park"
        self.assertEqual(self.log._parse_line(), (99, 'foo', 'Welcome to Jurassic Park'))

    def test_was_out_of_memory(self):
        # should be true
        self.log.result = "signal 15"
        self.assertTrue(self.log._was_out_of_memory())
        self.log.result = "exit 143"
        self.assertTrue(self.log._was_out_of_memory())

        # should be false
        self.log.result = "signal 8"
        self.assertFalse(self.log._was_out_of_memory())
        self.log.result = "exit 18"
        self.assertFalse(self.log._was_out_of_memory())

    def test_was_killed(self):
        # should be true
        self.log.result = "signal 9"
        self.assertTrue(self.log._was_killed())
        self.log.result = "exit 137"
        self.assertTrue(self.log._was_killed())

        # should be false
        self.log.result = "signal 8"
        self.assertFalse(self.log._was_killed())
        self.log.result = "exit 18"
        self.assertFalse(self.log._was_killed())

    def test_read_zzuf_log(self):
        (fd, f) = tempfile.mkstemp(text=True)
        line = "zzuf[s=%d,r=%s]: %s\n"
        os.write(fd, line % (10, "0.1-0.2", "foo"))
        os.write(fd, line % (85, "0.01-0.02", "bar"))
        os.close(fd)

        log = ZzufLog(f, self.outfile)

        self.assertEqual(log.seed, 85)
        self.assertEqual(log.range, "0.01-0.02")
        self.assertEqual(log.result, "bar")
        self.assertEqual(log.line, (line % (85, "0.01-0.02", "bar")).strip())

        # cleanup
        self.delete_file(f)

    def test_crash_logged(self):
        self.log.result = "a"
        self.log._set_exitcode()
        self.assertFalse(self.log.crash_logged(False))

        # _was_killed => true
        # should be false
        self.log.result = "signal 9"
        self.log._set_exitcode()
        self.assertFalse(self.log.crash_logged(False))

        # _was_out_of_memory => true
        # should be false
        self.log.result = "signal 15"
        self.log._set_exitcode()
        self.assertFalse(self.log.crash_logged(False))

        # should be false since infile is empty
        self.log.result = "a"
        self.log._set_exitcode()
        self.assertFalse(self.log.parsed)
        self.assertFalse(self.log.crash_logged(False))

        # should be true
        self.log.result = "a"
        self.log._set_exitcode()
        self.log.parsed = True # have to fake it since infile is empty
        self.assertTrue(self.log.crash_logged(False))

#    def test_crash_exit(self):
#        crash_exit_code_list = [77, 88, 99]
#
#        self.log.result = "exit 77"
#        self.log._set_exitcode()
#        self.assertTrue(self.log._crash_exit(crash_exit_code_list))
#
#        self.log.result = "exit 88"
#        self.log._set_exitcode()
#        self.assertTrue(self.log._crash_exit(crash_exit_code_list))
#
#        self.log.result = "exit 99"
#        self.log._set_exitcode()
#        self.assertTrue(self.log._crash_exit(crash_exit_code_list))
#
#        self.log.result = "exit 1"
#        self.log._set_exitcode()
#        self.assertFalse(self.log._crash_exit(crash_exit_code_list))
#
#        self.log.result = "exit 2"
#        self.log._set_exitcode()
#        self.assertFalse(self.log._crash_exit(crash_exit_code_list))
#
#        self.log.result = "exit 3"
#        self.log._set_exitcode()
#        self.assertFalse(self.log._crash_exit(crash_exit_code_list))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
