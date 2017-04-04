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
from test_certfuzz.mocks import MockCfg
import yaml
from certfuzz.file_handlers.seedfile_set import SeedfileSet
import json


class UnimplementedCampaign(CampaignBase):
    pass


class ImplementedCampaign(CampaignBase):

    def _do_interval(self):
        pass

    def _do_iteration(self):
        pass

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
        fd, cfgfile = tempfile.mkstemp(
            prefix='config_', suffix=".yaml", dir=self.tmpdir)
        os.close(fd)

        cfg = MockCfg(templated=False)
        with open(cfgfile, 'wb') as f:
            yaml.dump(cfg, f)
        self.campaign = ImplementedCampaign(cfgfile)

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
        self.assertTrue(
            self.campaign.seed_dir_local.startswith(self.campaign.working_dir))
        self.assertTrue(self.campaign.seed_dir_local.endswith('seedfiles'))

    def test_cleanup_workdir(self):
        self.campaign.work_dir_base = self.tmpdir
        self.campaign._setup_workdir()
        self.assertTrue(os.path.isdir(self.campaign.working_dir))
        self.campaign._cleanup_workdir()
        self.assertFalse(os.path.exists(self.campaign.working_dir))

    def test_crash_is_unique(self):
        self.assertEqual(0, len(self.campaign.testcases_seen))
        self.assertTrue(self.campaign._testcase_is_unique(1))
        self.assertEqual(1, len(self.campaign.testcases_seen))
        self.assertFalse(self.campaign._testcase_is_unique(1))
        self.assertEqual(1, len(self.campaign.testcases_seen))
        self.assertTrue(self.campaign._testcase_is_unique(2))
        self.assertEqual(2, len(self.campaign.testcases_seen))
        self.assertFalse(self.campaign._testcase_is_unique(2))
        self.assertEqual(2, len(self.campaign.testcases_seen))

        for x in [1, 2]:
            self.assertTrue(x in self.campaign.testcases_seen)

    def test_keep_going(self):
        for _x in range(100):
            self.assertTrue(self.campaign._keep_going())

    def _check_data_structure(self, x):
        for k in ['current_seed', 'config_timestamp', 'seedfile_scores', 'rangefinder_scores']:
            self.assertTrue(k in x)

        self.assertEqual(x['current_seed'], self.campaign.current_seed)
        self.assertEqual(
            x['config_timestamp'], self.campaign.config['config_timestamp'])

        self.assertEqual(
            len(x['rangefinder_scores']), len(self.campaign.seedfile_set.arms))

        self.assertEqual(
            len(x['seedfile_scores']), len(self.campaign.seedfile_set.arms))

        # verify the data structures
        for score in list(x['seedfile_scores'].values()):
            for k in ['successes', 'trials', 'probability']:
                self.assertTrue(k in score)

        for items in list(x['rangefinder_scores'].values()):
            for item in items:
                for k in ['range_key', 'range_score']:
                    self.assertTrue(k in item)
            score = item['range_score']
            for k in ['successes', 'trials', 'probability']:
                self.assertTrue(k in score)

    def _populate_sf_set(self):
        self.campaign.seedfile_set = SeedfileSet()

        files = []
        for x in range(10):
            _fd, _fname = tempfile.mkstemp(prefix='seedfile_', dir=self.tmpdir)
            os.write(_fd, str(x))
            os.close(_fd)
            files.append(_fname)

        self.campaign.seedfile_set.add_file(*files)

    def test_get_state_as_dict(self):
        self._populate_sf_set()
        x = self.campaign._get_state_as_dict()
        self._check_data_structure(x)

    def test_get_state_as_json(self):
        self._populate_sf_set()
        j = self.campaign._get_state_as_json()
        x = json.loads(j)
        self._check_data_structure(x)

    def test_save_state(self):
        fd, fpath = tempfile.mkstemp(
            suffix=".json", prefix="campaign_state_", dir=self.tmpdir)
        os.close(fd)
        os.remove(fpath)
        self.assertFalse(os.path.exists(fpath))

        self._populate_sf_set()
        self.campaign._save_state(fpath)
        self.assertTrue(os.path.exists(fpath))
        self.assertTrue(os.path.getsize(fpath) > 0)

        with open(fpath, 'rb') as f:
            x = json.load(f)

        self._check_data_structure(x)

        for k, v in self.campaign._get_state_as_dict().items():
            self.assertTrue(k in x)
            self.assertEqual(x[k], v)

    def test_read_state(self):
        fd, fpath = tempfile.mkstemp(
            suffix=".json", prefix="campaign_state_", dir=self.tmpdir)
        os.close(fd)
        self._populate_sf_set()
        d = self.campaign._get_state_as_dict()

        d['current_seed'] = 1000
        for score in d['seedfile_scores'].values():
            score['successes'] = 10
            score['trials'] = 100

        for sf in list(d['rangefinder_scores'].values()):
            for r in sf:
                r['range_score']['successes'] = 5
                r['range_score']['trials'] = 50

        with open(fpath, 'wb') as f:
            json.dump(d, f)

        self.assertNotEqual(self.campaign.current_seed, d['current_seed'])
        successes = [x['successes']
                     for x in list(self.campaign.seedfile_set.arms_as_dict().values())]
        for _score in successes:
            self.assertEqual(0, _score)
        trials = [x['trials']
                  for x in list(self.campaign.seedfile_set.arms_as_dict().values())]
        for _score in trials:
            self.assertEqual(0, _score)

        for sf in list(self.campaign.seedfile_set.things.values()):
            for r in list(sf.rangefinder.arms.values()):
                self.assertEqual(0, r.successes)
                self.assertEqual(0, r.trials)

        self.campaign._read_state(fpath)

        self.assertEqual(self.campaign.current_seed, d['current_seed'])
        successes = [x['successes']
                     for x in list(self.campaign.seedfile_set.arms_as_dict().values())]
        for _score in successes:
            self.assertEqual(10, _score)
        trials = [x['trials']
                  for x in list(self.campaign.seedfile_set.arms_as_dict().values())]
        for _score in trials:
            self.assertEqual(100, _score)

        for sf in list(self.campaign.seedfile_set.things.values()):
            for r in list(sf.rangefinder.arms.values()):
                self.assertEqual(5, r.successes)
                self.assertEqual(50, r.trials)

    def test_reject_cached_data_if_newer_config(self):
        fd, fpath = tempfile.mkstemp(
            suffix=".json", prefix="campaign_state_", dir=self.tmpdir)
        os.close(fd)
        self._populate_sf_set()
        d = self.campaign._get_state_as_dict()
        d['config_timestamp'] = d['config_timestamp'] - 1000.0
        with open(fpath, 'wb') as f:
            json.dump(d, f)

        self.assertEqual(2, self.campaign._read_state(fpath))

    def test_reject_cached_data_if_no_file(self):
        fd, fpath = tempfile.mkstemp(
            suffix=".json", prefix="campaign_state_", dir=self.tmpdir)
        os.close(fd)
        self.assertEqual(None, self.campaign._read_cached_data(fpath))
        os.remove(fpath)
        self.assertEqual(None, self.campaign._read_cached_data(fpath))


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
