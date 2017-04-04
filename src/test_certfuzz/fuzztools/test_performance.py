from certfuzz.fuzztools.performance import TimeStamper
import itertools

'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest

class Test(unittest.TestCase):

    def setUp(self):
        self.ts = TimeStamper()
        self.ts.start = 100.0
        self.ts.timestamps = [(101.0, 'a'), (104.14, 'b')]

    def tearDown(self):
        pass

    def test_timestamp(self):
        l = len(self.ts.timestamps)
        self.ts.timestamp('foo')
        self.assertEqual(len(self.ts.timestamps), l + 1)

    def test_get_timestamps(self):
        timestamps = self.ts.get_timestamps()
        self.assertEqual(len(timestamps), 2)
        self.assertAlmostEqual(timestamps[-1] - timestamps[0], 3.14, 2)

    def test_relative_to_start(self):
        [self.assertAlmostEqual(x, y) for (x, y) in zip(self.ts.relative_to_start(), (1.0, 4.14))]

    def test_deltas(self):
        self.ts.timestamps.append((106.0, 'c'))
        [self.assertAlmostEqual(x, y) for (x, y) in zip(self.ts.deltas(), (3.14, 1.86))]

    def test_delta_stats(self):
        self.ts.timestamps = [(4, 'a'), (5, 'b'), (7, 'c'), (8, 'd'), (9, 'e'), (12, 'f')]
        self.assertEqual(self.ts.delta_stats(), (1.6, 0.8))

    def test_last_ts(self):
        self.assertEqual(self.ts.last_ts(), 104.14)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
