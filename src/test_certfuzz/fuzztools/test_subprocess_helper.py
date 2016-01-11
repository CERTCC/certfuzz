'''
Created on Apr 8, 2011

@organization: cert.org
'''
import os
import tempfile
from certfuzz.fuzztools.subprocess_helper import run_with_timer
import unittest


class Test(unittest.TestCase):
    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def test_run_with_timer2(self):
        # we just want a tempfile name, not the actual file
        (fd, f) = tempfile.mkstemp(text=True)
        os.close(fd)
        self.delete_file(f)

        # we're going to try "touch <tmpfile>"
        args = ['touch', f]
        timeout = 10

        run_with_timer(args, timeout, 'touch')
        # if the file exists, we win!
        self.assertTrue(os.path.exists(f))

        # clean up
        self.delete_file(f)

        # try it again, with shell
        run_with_timer(args, timeout, 'touch', shell=True)
        # if the file exists, we win!
        self.assertTrue(os.path.exists(f))

        # clean up
        self.delete_file(f)

    def test_killall(self):
        #TODO: how do you test this?
        pass

    def test_kill(self):
        #TODO: how do you test this?
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
