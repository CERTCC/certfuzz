'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest
from certfuzz.fuzztools.range import Range
import pprint
import json

class Test(unittest.TestCase):
    def setUp(self):
        self.r = Range(0, 1)

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.r.max, 1.0)
        self.assertEqual(self.r.min, 0.0)
        self.assertEqual(self.r.mean, 0.5)
        self.assertEqual(self.r.span, 1.0)

    def test_repr(self):
        self.assertEqual(self.r.__repr__(), '0.000000-1.000000')

#    def test_getstate_is_pickle_friendly(self):
#        # getstate should return a pickleable object
#        import pickle
#        state = self.r.__getstate__()
#        try:
#            pickle.dumps(state)
#        except Exception, e:
#            self.fail('Failed to pickle state: %s' % e)
#
#    def test_getstate_has_all_expected_items(self):
#        state = self.r.__getstate__()
#        for k, v in self.r.__dict__.iteritems():
#            # make sure we're deleting what we need to
#            if k in ['logger']:
#                self.assertFalse(k in state)
#            else:
#                self.assertTrue(k in state, '%s not found' % k)
#                self.assertEqual(state[k], v)
#
#    def test_getstate(self):
#        state = self.r.__getstate__()
#        self.assertEqual(dict, type(state))
#        print 'as dict...'
#        pprint.pprint(state)
#
#    def test_to_json(self):
#        as_json = self.r.to_json(indent=4)
#
#        print 'as JSON...'
#        for l in as_json.splitlines():
#            print l
#
#        from_json = json.loads(as_json)
#
#        # make sure we can round-trip it
#        for k, v in self.r.__getstate__().iteritems():
#            self.assertTrue(k in from_json)
#            self.assertEqual(from_json[k], v)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
