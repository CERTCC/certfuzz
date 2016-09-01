'''
Created on Apr 15, 2011

@organization: cert.org
'''

import unittest
import tempfile
import os
from certfuzz.file_handlers.seedfile import SeedFile


class Test(unittest.TestCase):

    def setUp(self):
        (fd, self.file) = tempfile.mkstemp()
        self.dir = tempfile.mkdtemp()
        self.content = "I'm here and I'm ready. They're not. Bring it."
        os.write(fd, self.content)
        os.close(fd)
        self.sf = SeedFile(self.dir, self.file)

    def tearDown(self):
        os.remove(self.file)
        assert not os.path.exists(self.file)

    def test_init(self):
        pass


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
