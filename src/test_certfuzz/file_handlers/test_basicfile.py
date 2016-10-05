'''
Created on Mar 23, 2011

@organization: cert.org
'''
import unittest
import tempfile
import os
from certfuzz.file_handlers.basicfile import BasicFile
import hashlib
import shutil

class Test(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.emptymd5 = hashlib.md5('').hexdigest()

        (fd1, self.f1) = tempfile.mkstemp(dir=self.tempdir)
        os.close(fd1)
        self.emptybasicfile = BasicFile(self.f1)

        (fd2, self.f2) = tempfile.mkstemp(dir=self.tempdir)
        self.content = "I'm here and I'm ready. They're not. Bring it."
        os.write(fd2, self.content)
        os.close(fd2)
        self.basicfile = BasicFile(self.f2)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_basicfile_init(self):
        self.assertEqual(self.emptybasicfile.md5, self.emptymd5)
        self.assertEqual(self.emptybasicfile.len, 0)
        self.assertEqual(self.emptybasicfile.bitlen, 0)
        self.assertEqual(self.basicfile.md5, 'b8a17b44dec164d67685a9fe9817da90')
        self.assertEqual(self.basicfile.len, len(self.content))
        self.assertEqual(self.basicfile.bitlen, 8 * len(self.content))

    def test_refresh(self):
        fd = open(self.emptybasicfile.path, 'w')
        fd.write('Boom, crush. Night, losers. Winning, duh. ')
        fd.close()

        self.assertEqual(self.emptybasicfile.md5, self.emptymd5)
        self.assertEqual(self.emptybasicfile.len, 0)
        self.assertEqual(self.emptybasicfile.bitlen, 0)
        self.emptybasicfile.refresh()
        self.assertEqual(self.emptybasicfile.md5, '0281570ea703d7e39dab89319fe96202')
        self.assertEqual(self.emptybasicfile.len, 42)
        self.assertEqual(self.emptybasicfile.bitlen, 8 * 42)

    def test_read(self):
        self.assertEqual(self.basicfile.read(), self.content)

        # nonexistent file should raise an exception
        os.remove(self.basicfile.path)
        self.assertFalse(os.path.exists(self.basicfile.path))
        self.assertRaises(Exception, self.basicfile.read)

    def test_exists(self):
        self.assertTrue(self.emptybasicfile.exists())
        self.assertTrue(self.basicfile.exists())
        os.remove(self.f1)
        self.assertFalse(self.emptybasicfile.exists())
        self.assertTrue(self.basicfile.exists())
        os.remove(self.f2)
        self.assertFalse(self.emptybasicfile.exists())
        self.assertFalse(self.basicfile.exists())

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.test_init']
    unittest.main()
