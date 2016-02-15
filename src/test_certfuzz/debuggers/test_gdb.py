import tempfile
'''
Created on Apr 8, 2011

@organization: cert.org
'''
import os
import unittest

from certfuzz.debuggers.gdb import GDB

class Test(unittest.TestCase):
    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def setUp(self):
        (program, cmd_args, gdb_file, timeout) = tuple('abcde')
        (fd, path) = tempfile.mkstemp()
        os.close(fd)
        self.tempfile = path

        self.gdb = GDB(program, cmd_args, gdb_file, timeout, template=self.tempfile)
        self.gdb._create_input_file()

    def tearDown(self):
        if os.path.exists(self.gdb.input_file):
            self.delete_file(self.gdb.input_file)
        if os.path.exists(self.tempfile):
            self.delete_file(self.tempfile)

    def test_get_gdb_cmdline(self):
        self.gdb._create_input_file()
        expected = ['gdb', '-n', '-batch', '-command', self.gdb.input_file]
        self.assertEqual(self.gdb._get_cmdline(), expected)

    def test_get_gdb(self):
        # cannot test directly, see test_get_gdb_cmdline() and test_create_gdb_input_file()
        pass

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
