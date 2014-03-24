'''
Created on Mar 23, 2012

@organization: cert.org
'''

import unittest
from certfuzz.campaign import campaign
from tempfile import mkstemp, mkdtemp
import yaml
import shutil
import os
import tempfile
from certfuzz.fuzztools import filetools


class Mock(object):
    def __getstate__(self):
        return dict(x=1, y=2, z=3)


class Test(unittest.TestCase):

    def _dump_test_config(self):
        cfg = {'campaign': {
                           'id': 'campaign_id',
                           'keep_heisenbugs': True,
                           'cached_state_file': mkstemp(dir=self.tmpdir)[1],
                           },
            'target': {
                'cmdline_template': 'cmdline_template',
                'program': self.program},
            'runoptions': {
                'first_iteration': 0,
                'last_iteration': 100,
                'seed_interval': 5,
                'keep_all_duplicates': True,
                'keep_unique_faddr': True},
            'directories': {
                'results_dir': mkdtemp(dir=self.tmpdir),
                'working_dir': mkdtemp(dir=self.tmpdir),
                'seedfile_dir': mkdtemp(dir=self.tmpdir)},
            'fuzzer': {
                'fuzzer': 'fuzzermodule'},
            'runner': {
                'runner': 'runnermodule'},
            'debugger': {
                'debugger': 'debuggermodule'}}
        self.cfg_file = mkstemp(dir=self.tmpdir)[1]
        with open(self.cfg_file, 'wb') as output:
            yaml.dump(cfg, stream=output)

    def setUp(self):
        self.tmpdir = mkdtemp()
        self.program = mkstemp(dir=self.tmpdir)[1]
        self._dump_test_config()
        self.campaign = campaign.Campaign(self.cfg_file)

        fd, f = tempfile.mkstemp()
        os.close(fd)
        os.remove(f)
        self.campaign.cached_state_file = f

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_init(self):
        self.assertEqual('%s.%s' % (campaign.packages['fuzzers'], 'fuzzermodule'),
                         self.campaign.fuzzer_module_name)
        self.assertEqual('%s.%s' % (campaign.packages['runners'], 'runnermodule'),
                         self.campaign.runner_module_name)
        self.assertEqual('%s.%s' % (campaign.packages['debuggers'], 'debuggermodule'),
                         self.campaign.debugger_module_name)

#    def test_getstate(self):
#        self.campaign.seedfile_set = Mock()
#
#        # get_state should return a pickleable result
#        state = self.campaign.__getstate__()
#
#        import pickle
#        try:
#            pickle.dumps(state)
#        except Exception, e:
#            self.fail(e)

    def counter(self, *args):
        self.count += 1

#    def test_save_state(self):
#
#        # make sure we can write
#        self.assertFalse(os.path.exists(self.campaign.cached_state_file))
#        self.campaign._save_state()
#        self.assertTrue(os.path.exists(self.campaign.cached_state_file))
#
#    def test_set_state(self):
#        state = {'crashes_seen': [1, 2, 3, 3],
#                 'seedfile_set': {'things': {}},
#                 'id': 2134,
#                 'seed_dir_in': mkdtemp(dir=self.tmpdir),
#                 'seed_dir_local': mkdtemp(dir=self.tmpdir),
#                 'sf_set_out': tempfile.mktemp(dir=self.tmpdir)[1],
#                 }
#        self.campaign.__setstate__(state)
#        self.assertEqual(self.campaign.crashes_seen, set([1, 2, 3]))

    def test_write_version(self):
        vf = os.path.join(self.campaign.outdir, 'version.txt')
        filetools.make_directories(self.campaign.outdir)
        self.assertTrue(os.path.isdir(self.campaign.outdir))
        self.assertFalse(os.path.exists(vf))
        self.campaign._write_version()
        self.assertTrue(os.path.exists(vf))
        self.assertTrue(os.path.getsize(vf) > 0)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
