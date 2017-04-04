'''
Created on Apr 14, 2011

@organization: cert.org
'''
import unittest
import tempfile
import os
import shutil

from certfuzz.file_handlers.seedfile_set import SeedfileSet
from certfuzz.file_handlers.directory import Directory
from certfuzz.file_handlers.seedfile import SeedFile


class Test(unittest.TestCase):

    def setUp(self):
        campaign_id = 'testcampaign'

        self.origindir = tempfile.mkdtemp()
        self.localdir = tempfile.mkdtemp()
        self.outputdir = tempfile.mkdtemp()

        # create some files
        self.file_count = 5
        self.files = []
        for i in range(self.file_count):
            (fd, f) = tempfile.mkstemp(dir=self.origindir)

            os.write(fd, 'abacab%d' % i)
            os.close(fd)
            self.files.append(f)

        # create a set
        self.sfs = SeedfileSet(
            campaign_id, self.origindir, self.localdir, self.outputdir)

    def tearDown(self):
        for f in self.files:
            os.remove(f)
            self.assertFalse(os.path.exists(f))
        for d in (self.origindir, self.localdir, self.outputdir):
            shutil.rmtree(d)
            self.assertFalse(os.path.exists(d))

#    def test_pickle(self):
#        import pickle
#        self.assertTrue(hasattr(self.sfs, 'things'))
#        # no files added yet
#        self.assertEqual(0, len(self.sfs.things))
#        # add the files
#        self.sfs._setup()
#        # confirm that the files are there
#        self.assertEqual(self.file_count, len(self.sfs.things))
#        unpickled = pickle.loads(pickle.dumps(self.sfs))
#
#        self.assertTrue(hasattr(unpickled, 'things'))
#        self.assertEqual(self.file_count, len(unpickled.things))

    def test_set_directories(self):
        self.assertEqual(self.sfs.originpath, self.origindir)
        self.assertEqual(self.sfs.localpath, self.localdir)
        self.assertEqual(self.sfs.outputpath, self.outputdir)
        self.assertEqual(None, self.sfs.origindir)
        self.assertEqual(None, self.sfs.localdir)
        self.assertEqual(None, self.sfs.outputdir)

        self.sfs._set_directories()

        self.assertEqual(Directory, self.sfs.origindir.__class__)
        self.assertEqual(Directory, self.sfs.localdir.__class__)
        self.assertEqual(Directory, self.sfs.outputdir.__class__)

        # make sure the file(s) we created in setUp are in origindir
        self.assertEqual(self.file_count, len(self.sfs.origindir.files))

    def test_copy_files_to_localdir(self):
        # mock the things
        self.sfs.origindir = [1, 2, 3, 4, 5]
        copied = []
        self.sfs.copy_file_from_origin = lambda x: copied.append(x)
        # do the test
        self.sfs._copy_files_to_localdir()
        self.assertEqual(self.sfs.origindir, copied)

    def test_copy_file_from_origin(self):
        pass

    def test_add_local_files_to_set(self):
        pass

    def test_add_file(self):
        self.assertNotEqual(0, len(self.files))
        self.assertEqual(0, len(self.sfs.things))
        self.sfs.add_file(*self.files)
        self.assertEqual(5, len(self.sfs.things))
        for thing in self.sfs.things.values():
            self.assertEqual(SeedFile, thing.__class__)

    def test_init(self):
        self.assertEqual(self.outputdir, self.sfs.seedfile_output_base_dir)
        self.assertEqual(0, len(self.sfs.things))

    def _same_dict(self, d1, d2):
        for k, v in d1.items():
            #            print k
            self.assertTrue(k in d2)
            self.assertEqual(v, d2[k])


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
