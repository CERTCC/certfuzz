'''
Created on Apr 14, 2011

@organization: cert.org
'''
import unittest
import tempfile
import os
import shutil
from pprint import pprint

from certfuzz.file_handlers.seedfile_set import SeedfileSet
from certfuzz.file_handlers.directory import Directory
from certfuzz.file_handlers.seedfile import SeedFile
import hashlib
from certfuzz.scoring.scorable_set import EmptySetError
#from pprint import pprint


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
        self.sfs = SeedfileSet(campaign_id, self.origindir, self.localdir, self.outputdir)

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
        for thing in self.sfs.things.itervalues():
            self.assertEqual(SeedFile, thing.__class__)

    def test_init(self):
        self.assertEqual(self.outputdir, self.sfs.seedfile_output_base_dir)
        self.assertEqual(0, len(self.sfs.things))

#    def test_getstate_is_pickle_friendly(self):
#        # getstate should return a pickleable object
#        import pickle
#        state = self.sfs.__getstate__()
#        try:
#            pickle.dumps(state)
#        except Exception, e:
#            self.fail('Failed to pickle state: %s' % e)
#
#    def test_getstate(self):
#        state = self.sfs.__getstate__()
#        self.assertEqual(dict, type(state))
#
#        for k in self.sfs.__dict__.iterkeys():
#            # make sure we're deleting what we need to
#            if k in ['localdir', 'origindir', 'outputdir']:
#                self.assertFalse(k in state)
#            else:
#                self.assertTrue(k in state, '%s not found' % k)

#    def test_setstate(self):
#        self.sfs.__enter__()
#        state_before = self.sfs.__getstate__()
#        self.sfs.__setstate__(state_before)
#        self.assertEqual(self.file_count, self.sfs.sfcount)
#        state_after = self.sfs.__getstate__()
#
#        for k, v in state_before.iteritems():
#            self.assertTrue(k in state_after)
#            if not k == 'things':
#                self.assertEqual(v, state_after[k])
#
#        for k, thing in state_before['things'].iteritems():
#            # is there a corresponding thing in sfs?
#            self.assertTrue(k in self.sfs.things)
#
#            for x in thing.iterkeys():
#                # was it set correctly?
#                self.assertEqual(thing[x], self.sfs.things[k].__dict__[x])
#
#        self.assertEqual(self.file_count, self.sfs.sfcount)

#    def test_setstate_with_changed_files(self):
#        # refresh the sfs
#        self.sfs.__enter__()
#
#        # get the original state
#        state_before = self.sfs.__getstate__()
#        self.assertEqual(len(state_before['things']), self.file_count)
#
#        # delete one of the files
#        file_to_remove = self.files.pop()
#        localfile_md5 = hashlib.md5(open(file_to_remove, 'rb').read()).hexdigest()
#        localfilename = "sf_%s" % localfile_md5
#
#        # remove it from origin
#        os.remove(file_to_remove)
#        self.assertFalse(file_to_remove in self.files)
#        self.assertFalse(os.path.exists(file_to_remove))
##        print "removed %s" % file_to_remove
#
##        # remove it from localdir
#        localfile_to_remove = os.path.join(self.localdir, localfilename)
#        os.remove(localfile_to_remove)
#        self.assertFalse(os.path.exists(localfile_to_remove))
#
#        # create a new sfs
#        new_sfs = SeedfileSet()
#        new_sfs.__setstate__(state_before)
#
#        self.assertEqual(len(new_sfs.things), (self.file_count - 1))
#
##        print "Newthings: %s" % new_sfs.things.keys()
#        for k, thing in state_before['things'].iteritems():
##            print "k: %s" % k
#            if k == localfile_md5:
#                self.assertFalse(k in new_sfs.things)
#                continue
#            else:
#                # is there a corresponding thing in sfs?
#                self.assertTrue(k in new_sfs.things)
#
#            for x, y in thing.iteritems():
#                # was it set correctly?
#                sfsthing = new_sfs.things[k].__dict__[x]
#                if hasattr(sfsthing, '__dict__'):
#                    # some things are complex objects themselves
#                    # so we have to compare their __dict__ versions
#                    self._same_dict(y, sfsthing.__dict__)
#                else:
#                    # others are just simple objects and we can
#                    # compare them directly
#                    self.assertEqual(y, sfsthing)
#
#        self.assertEqual(self.file_count - 1, new_sfs.sfcount)

    def _same_dict(self, d1, d2):
        for k, v in d1.iteritems():
#            print k
            self.assertTrue(k in d2)
            if not v == d2[k]:
                pprint(v)
                pprint(d2[k])

            self.assertEqual(v, d2[k])

#    def test_next_item(self):
#        self.assertEqual(0, len(self.sfs.things))
#        self.assertRaises(EmptySetError, self.sfs.next_key)
#        self.assertRaises(EmptySetError, self.sfs.next_item)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
