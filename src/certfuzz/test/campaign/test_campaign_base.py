'''
Created on Mar 23, 2012

@organization: cert.org
'''

import unittest
from tempfile import mkdtemp
import shutil
import os
from certfuzz.fuzztools import filetools
from certfuzz.campaign.campaign_base import CampaignBase
import tempfile
from certfuzz.campaign.errors import CampaignError


class UnimplementedCampaign(CampaignBase):
    pass


class ImplementedCampaign(CampaignBase):
    def __getstate__(self):
        pass

    def __init__(self, config_file, result_dir=None):
        return CampaignBase.__init__(self, config_file, result_dir)

    def  __setstate__(self):
        pass

    def _do_interval(self):
        pass

    def _do_iteration(self):
        pass

    def _handle_errors(self):
        pass

    def _keep_going(self):
        return CampaignBase._keep_going(self)

    def _post_enter(self):
        pass

    def _pre_enter(self):
        pass

    def _pre_exit(self):
        pass

    def _set_debugger(self):
        pass

    def _set_fuzzer(self):
        pass

    def _set_runner(self):
        pass


class Test(unittest.TestCase):
    def setUp(self):
        self.tmpdir = mkdtemp()
        _fd, cfgfile = tempfile.mkstemp(suffix=".cfg", dir=self.tmpdir, text=True)
        try:
            self.campaign = ImplementedCampaign(cfgfile)
        except TypeError as e:
            self.fail('ImplementedCampaign does not match requirements: {}'.format(e))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_metaclass(self):
        self.assertRaises(TypeError, UnimplementedCampaign)

    def test_write_version(self):
        self.campaign.outdir = self.tmpdir
        vf = self.campaign._version_file
        filetools.make_directories(self.campaign.outdir)
        self.assertTrue(os.path.isdir(self.campaign.outdir))
        self.assertFalse(os.path.exists(vf))
        self.campaign._write_version()
        self.assertTrue(os.path.exists(vf))
        self.assertTrue(os.path.getsize(vf) > 0)

    def test_check_prog(self):
        fd, f = tempfile.mkstemp(dir=self.tmpdir)
        os.close(fd)
        self.campaign.program = f
        try:
            self.assertTrue(os.path.exists(f))
            self.campaign._check_prog()
        except CampaignError as e:
            self.fail('File {} exists but _check_prog failed: {}'.format(f, e))

        # now try it when the file is gone
        os.remove(f)
        self.assertFalse(os.path.exists(f))
        self.assertRaises(CampaignError, self.campaign._check_prog)

    def test_setup_output(self):
        self.campaign.outdir = tempfile.mkdtemp(dir=self.tmpdir)
        shutil.rmtree(self.campaign.outdir)
        self.assertFalse(os.path.exists(self.campaign.outdir))
        self.campaign._setup_output()
        self.assertTrue(os.path.isdir(self.campaign.outdir))
        self.assertTrue(os.path.isfile(self.campaign._version_file))

    def test_setup_workdir(self):
        self.campaign.work_dir_base = tempfile.mkdtemp(dir=self.tmpdir)
        shutil.rmtree(self.campaign.work_dir_base)
        self.assertFalse(os.path.exists(self.campaign.work_dir_base))
        self.assertEqual(None, self.campaign.working_dir)
        self.assertEqual(None, self.campaign.seed_dir_local)
        self.campaign._setup_workdir()
        self.assertTrue(os.path.isdir(self.campaign.work_dir_base))
        self.assertTrue(os.path.isdir(self.campaign.working_dir))
        self.assertTrue(self.campaign.seed_dir_local.startswith(self.campaign.working_dir))
        self.assertTrue(self.campaign.seed_dir_local.endswith('seedfiles'))

    def test_cleanup_workdir(self):
        self.campaign.work_dir_base = self.tmpdir
        self.campaign._setup_workdir()
        self.assertTrue(os.path.isdir(self.campaign.working_dir))
        self.campaign._cleanup_workdir()
        self.assertFalse(os.path.exists(self.campaign.working_dir))

    def test_crash_is_unique(self):
        self.assertEqual(0, len(self.campaign.crashes_seen))
        self.assertTrue(self.campaign._crash_is_unique(1))
        self.assertEqual(1, len(self.campaign.crashes_seen))
        self.assertFalse(self.campaign._crash_is_unique(1))
        self.assertEqual(1, len(self.campaign.crashes_seen))
        self.assertTrue(self.campaign._crash_is_unique(2))
        self.assertEqual(2, len(self.campaign.crashes_seen))
        self.assertFalse(self.campaign._crash_is_unique(2))
        self.assertEqual(2, len(self.campaign.crashes_seen))

        for x in [1, 2]:
            self.assertTrue(x in self.campaign.crashes_seen)

    def test_keep_going(self):
        for _x in range(100):
            self.assertTrue(self.campaign._keep_going())


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
