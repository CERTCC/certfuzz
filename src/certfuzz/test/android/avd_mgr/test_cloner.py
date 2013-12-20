# '''
# Created on Jan 18, 2013
#
# @organization: cert.org
# '''
# import unittest
# from certfuzz.android.avd_mgr import cloner
# from certfuzz.android.avd_mgr.errors import AvdClonerError
# import tempfile
# import shutil
# import os
# from certfuzz.android.api.defaults import avddir, avddir_basename
#
# class Test(unittest.TestCase):
#
#     def setUp(self):
#         self.c = cloner.AvdCloner()
#         self.tmpdir = tempfile.mkdtemp()
#
#     def tearDown(self):
#         shutil.rmtree(self.tmpdir)
#
#     def test_init(self):
#         c = self.c
#         self.assertNotEqual(None, c.dst)
#         self.assertTrue(c.remove)
#         self.assertEqual(0, len(c._removables))
#
#     def test_enter(self):
#         c = self.c
#         self.assertEqual(None, c.src)
#         self.assertRaises(AvdClonerError, c.__enter__)
#         c.src = 'foo'
#         self.assertEqual(c, c.__enter__())
#
#     def test_remove(self):
#         c = self.c
#         # add a file
#         fd, f = tempfile.mkstemp(dir=self.tmpdir)
#         os.close(fd)
#         c._removables.append(f)
#         # add a dir
#         d = tempfile.mkdtemp(dir=self.tmpdir)
#         c._removables.append(d)
#         # test it
#         self.assertTrue(os.path.exists(f))
#         self.assertTrue(os.path.exists(d))
#         c._remove()
#         self.assertFalse(os.path.exists(f))
#         self.assertFalse(os.path.exists(d))
#
#         # make sure it doesn't choke on nonexistent files/dirs
#         c._remove()
#
#     def test_set_paths(self):
#         c = self.c
#
#         # raise error if src not set
#         c.src = None
#         c.dst = 'bar'
#         self.assertRaises(AvdClonerError, c._set_paths)
#
#         # raise error if neither src nor dst set
#         c.src = None
#         c.dst = None
#         self.assertRaises(AvdClonerError, c._set_paths)
#
#         # raise error if just dst not set
#         c.src = 'foo'
#         c.dst = None
#         self.assertRaises(AvdClonerError, c._set_paths)
#
#         c.src = 'foo'
#         c.dst = 'bar'
#         c._set_paths()
#         self.assertEqual('foo.avd', os.path.basename(c._src_avddir))
#         self.assertEqual('bar.avd', os.path.basename(c._dst_avddir))
#         self.assertEqual('foo.ini', os.path.basename(c._src_inifile))
#         self.assertEqual('bar.ini', os.path.basename(c._dst_inifile))
#
#     def test_clone_avd_dir(self):
#         c = self.c
#         c.src = tempfile.mkdtemp(dir=self.tmpdir)
#         c._set_paths()
#
#         # raise exception if src doesn't exist
#         self.assertEqual(0, len(c._removables))
#         self.assertFalse(os.path.exists(c._src_avddir))
#         self.assertRaises(OSError, c._clone_avd_dir)
#         self.assertEqual(0, len(c._removables))
#
#         # raise exception if dst already exists
#         c._src_avddir = tempfile.mkdtemp(dir=self.tmpdir)
#         c._dst_avddir = tempfile.mkdtemp(dir=self.tmpdir)
#         self.assertTrue(os.path.exists(c._src_avddir))
#         self.assertTrue(os.path.exists(c._dst_avddir))
#         self.assertRaises(OSError, c._clone_avd_dir)
#         self.assertEqual(0, len(c._removables))
#
#         # create a file in src
#         fd, f = tempfile.mkstemp(dir=c._src_avddir)
#         basename = os.path.basename(f)
#         dstfile = os.path.join(c._dst_avddir, basename)
#         # make sure target does not exist
#         shutil.rmtree(c._dst_avddir)
#         self.assertFalse(os.path.exists(c._dst_avddir))
#         self.assertFalse(os.path.exists(dstfile))
#         self.assertEqual(0, len(c._removables))
#         c._clone_avd_dir()
#         self.assertTrue(os.path.exists(c._dst_avddir))
#         self.assertTrue(os.path.exists(dstfile))
#         self.assertNotEqual(0, len(c._removables))
#         self.assertTrue(c._dst_avddir in c._removables)
#
#     def test_clone_ini_file(self):
#         c = self.c
#         c.src = tempfile.mkdtemp(dir=self.tmpdir)
#         c._set_paths()
#         self.assertEqual(0, len(c._removables))
#
#         fd, f = tempfile.mkstemp(dir=self.tmpdir)
#         os.close(fd)
#         c._src_inifile = f
#
#         fd, f = tempfile.mkstemp(dir=self.tmpdir)
#         os.close(fd)
#         os.remove(f)
#         c._dst_inifile = f
#
#         # src exists, dst doesn't, should succeed
#         self.assertFalse(os.path.exists(c._dst_inifile))
#         c._removables = []
#         c._clone_ini_file()
#         self.assertTrue(os.path.exists(c._dst_inifile))
#         self.assertTrue(c._dst_inifile in c._removables)
#
#         # src exists, dst exists, should succeed
#         c._removables = []
#         c._clone_ini_file()
#         self.assertTrue(os.path.exists(c._dst_inifile))
#         self.assertTrue(c._dst_inifile in c._removables)
#
#         # src does not exist, should fail
#         os.remove(c._src_inifile)
#         self.assertRaises(IOError, c._clone_ini_file)
#         os.remove(c._dst_inifile)
#         self.assertRaises(IOError, c._clone_ini_file)
#
#     def test_fix_ini(self):
#         c = self.c
#         # write an ini file
#         fd, f = tempfile.mkstemp(dir=self.tmpdir, text=True)
#         doc = "AAAAA\npath=foo\nBBBBB\n"
#         os.write(fd, doc)
#         os.close(fd)
#         c._dst_inifile = f
#
#         c._dst_avddir = self.tmpdir
#
#         # expected: path=foo replaced by path=bar, all other lines untouched
#         c._fix_ini()
#         self.assertTrue(os.path.exists(c._dst_inifile))
#         with open(c._dst_inifile, 'r') as f:
#             content = f.read()
#             self.assertFalse('foo' in content)
#
#             lines = content.splitlines()
#             self.assertEqual('AAAAA', lines[0])
#             self.assertEqual('path=%s' % self.tmpdir, lines[1])
#             self.assertEqual('BBBBB', lines[2])
#             self.assertEqual(3, len(lines))
#
# if __name__ == "__main__":
#     # import sys;sys.argv = ['', 'Test.testName']
#     unittest.main()
