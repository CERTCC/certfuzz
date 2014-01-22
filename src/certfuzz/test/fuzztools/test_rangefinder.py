'''
Created on Apr 8, 2011

@organization: cert.org
'''

import os
import tempfile
import unittest

from certfuzz.fuzztools.rangefinder import RangeFinder


class Test(unittest.TestCase):
    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def setUp(self):
        self.min = 0.001
        self.max = 0.999
        (fd, f) = tempfile.mkstemp(text=True)
        os.close(fd)
        self.tmpfile = f
        self.r = RangeFinder(self.min, self.max, self.tmpfile)

    def tearDown(self):
        self.delete_file(self.tmpfile)

    def test_get_ranges(self):
        ranges = self._ranges()

        # the high end of the last range should be the max
        self.assertAlmostEqual(ranges[-1].max, self.max)

        # the low end of the first range should be the min
        self.assertAlmostEqual(ranges[0].min, self.min)

        # make sure the internal ranges match up
        for (this, next_element) in zip(ranges[:-1], ranges[1:]):
            self.assertEqual(this.max, next_element.min)

        # Ranges would be 0.375-0.601, 0.601-0.981, 0.981-0.999
        # if it weren't for the fix that merges the last two
        # so we should only see two ranges
        r = RangeFinder(0.375, 0.999, self.tmpfile)
        self.assertEqual(len(r.things), 2)
        ranges = [v for (dummy, v) in sorted(r.things.items())]
        self.assertAlmostEqual(ranges[0].min, 0.375)
        self.assertAlmostEqual(ranges[1].max, 0.999)

    def _ranges(self):
        keys = sorted(self.r.things.keys())
        return [self.r.things[k] for k in keys]

    def test_range_orderings(self):
        # first term should be smaller than second term
        ranges = self.r.things.values()
        [self.assertTrue(x.min <= x.max) for x in ranges]

    def test_range_overlaps(self):
        # this one's min should be the next_element one's max
        ranges = self._ranges()
        [self.assertEqual(x.min, y.max) for (x, y) in zip(ranges[1:], ranges[:-1])]

    def test_range_mean(self):
        # mean should be halfway between min and max
        [self.assertAlmostEqual(x.mean, ((x.max + x.min) / 2)) for x in self.r.things.values()]

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
#                self.assertEqual(type(state[k]), type(v))
#
#    def test_getstate(self):
#        state = self.r.__getstate__()
#        self.assertEqual(dict, type(state))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
