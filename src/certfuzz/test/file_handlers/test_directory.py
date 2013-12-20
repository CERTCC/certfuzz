'''
Created on Mar 18, 2011

@organization: cert.org
'''
import unittest
import tempfile
import os
import shutil
from certfuzz.file_handlers.directory import Directory, DirectoryError
import logging

logger = logging.getLogger(__name__)

class Test(unittest.TestCase):

    def setUp(self):
        self.path = tempfile.mkdtemp()
        self.assertTrue(os.path.isdir(self.path))
        # drop some files in the dir
        self.files = [os.path.join(self.path, filename) for filename in ('a', 'b', 'c')]
        [open(f, 'w') for f in self.files]
        self.directory = Directory(self.path)

    def tearDown(self):
        if os.path.isdir(self.path):
            shutil.rmtree(self.path)
        self.assertFalse(os.path.isdir(self.path))
        self.assertFalse(os.path.exists(self.path))

    def test_verify_dir(self):
        self.assertTrue(os.path.exists(self.path))
        self.assertTrue(os.path.isdir(self.path))
        # verify should fail if the dir doesn't exist
        shutil.rmtree(self.path)
        self.assertRaises(DirectoryError, self.directory._verify_dir)

        # verify should fail if the path is not a dir
        open(self.path, 'w')
        self.assertTrue(os.path.exists(self.path))
        self.assertFalse(os.path.isdir(self.path))
        self.assertRaises(DirectoryError, self.directory._verify_dir)

        # clean up
        os.remove(self.path)
        self.assertFalse(os.path.exists(self.path))

    def test_refresh(self):
        # make sure we got the files we created in setup
        for f in self.files:
            self.assertTrue(f in self.directory.paths())

        # create a new file, then test to see if it shows up in a refresh
        newfile = os.path.join(self.path, 'x')
        open(newfile, 'w').write('AAAA')

        self.assertFalse(newfile in self.directory.paths())
        self.directory.refresh()
        self.assertTrue(newfile in self.directory.paths())

    def test_symlinked_dir(self):
        # dir is symlink, link target exists but is not dir
        target_file = tempfile.mktemp()
        self.assertFalse(os.path.exists(target_file))
        open(target_file, 'w')
        self.assertTrue(os.path.exists(target_file))
        self.assertTrue(os.path.isfile(target_file))

        link_name = tempfile.mktemp()
        self.assertFalse(os.path.exists(link_name))
        os.symlink(target_file, link_name)
        self.assertTrue(os.path.exists(link_name))
        self.assertTrue(os.path.islink(link_name))
        self.assertTrue(os.path.isfile(link_name))

        self.assertRaises(DirectoryError, Directory, link_name)
        os.remove(link_name)
        os.remove(target_file)

        # dir is symlink, link target is dir
        target_dir = tempfile.mkdtemp()
        self.assertTrue(os.path.isdir(target_dir))
        link_name = tempfile.mktemp()
        self.assertFalse(os.path.exists(link_name))
        os.symlink(target_dir, link_name)
        self.assertTrue(os.path.exists(link_name))
        self.assertTrue(os.path.islink(link_name))
        self.assertTrue(os.path.isdir(link_name))

        d = Directory(link_name)
        self.assertEqual(link_name, d.dir)

        # remove the target dir - now we have a bad link
        os.rmdir(target_dir)
        self.assertFalse(os.path.exists(target_dir))

        # dir is symlink, link target does not exist
        self.assertTrue(os.path.islink(link_name))
        self.assertFalse(os.path.exists(os.readlink(link_name)))
        self.assertRaises(DirectoryError, Directory, link_name, True)

        os.remove(link_name)
        self.assertFalse(os.path.exists(link_name))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
