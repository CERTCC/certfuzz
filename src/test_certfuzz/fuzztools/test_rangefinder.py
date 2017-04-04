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
        self.r = RangeFinder(self.min, self.max)

    def tearDown(self):
        self.delete_file(self.tmpfile)

    def test_get_ranges(self):
        ranges = self._ranges()

        # the high end of the last range should be the max
        self.assertAlmostEqual(ranges[-1].max, self.max, 3)

        # the low end of the first range should be the min
        self.assertAlmostEqual(ranges[0].min, self.min, 3)

        # make sure the internal ranges match up
        for (this, next_element) in zip(ranges[:-1], ranges[1:]):
            self.assertEqual(this.max, next_element.min)

        # Ranges would be 0.375-0.601, 0.601-0.981, 0.981-0.999
        # if it weren't for the fix that merges the last two
        # so we should only see two ranges
        r = RangeFinder(0.375, 0.999)
        self.assertEqual(len(r.things), 2)
        mins = sorted([thing.min for thing in r.things.values()])
        maxs = sorted([thing.max for thing in r.things.values()])
        self.assertEqual(0.375, mins[0])
        self.assertAlmostEqual(0.61, mins[1], places=2)
        self.assertAlmostEqual(0.61, maxs[0], places=2)
        self.assertEqual(0.999, maxs[1])

    def _ranges(self):
        minkeys = sorted([(v.min, k) for (k, v) in self.r.things.items()])
        keys = [k[1] for k in minkeys]
        return [self.r.things[k] for k in keys]

    def test_range_orderings(self):
        # first term should be smaller than second term
        ranges = list(self.r.things.values())
        for x in ranges:
            self.assertTrue(x.min <= x.max)

    def test_range_overlaps(self):
        # this one's min should be the next_element one's max
        ranges = self._ranges()
        for (x, y) in zip(ranges[1:], ranges[:-1]):
            self.assertEqual(x.min, y.max)

    def test_range_mean(self):
        # mean should be halfway between min and max
        for x in list(self.r.things.values()):
            self.assertAlmostEqual(x.mean, ((x.max + x.min) / 2))


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
