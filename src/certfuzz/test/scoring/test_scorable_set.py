'''
Created on Mar 26, 2012

@organization: cert.org
'''

import unittest
import random
import tempfile

from certfuzz.scoring.scorable_set import ScorableSet2
from certfuzz.scoring.errors import ScorableSetError, EmptySetError
from certfuzz.helpers import random_str
import os
import shutil
import csv

class MockScorableThing(object):
    def __init__(self):
        self.key = random_str(8)
        self.probability = random.uniform(0.0, 1.0)


class Test(unittest.TestCase):

    def setUp(self):
        self.ss = ScorableSet2()
        self.things = []
        self.tmpdir = tempfile.mkdtemp()
        fd, f = tempfile.mkstemp(dir=self.tmpdir)
        os.close(fd)
        os.remove(f)
        self.tmpfile = f

        for _x in xrange(5):
            thing = MockScorableThing()
            self.ss.add_item(thing.key, thing)
            self.things.append(thing)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_scaled_score(self):
        self.ss._update_probabilities()
        score_sum = sum([x for x in self.ss.scaled_score.itervalues()])
        self.assertAlmostEqual(score_sum, 1.0)

    def test_del_item(self):
        # progressively delete all the things and make sure they go away
        # as expected
        while self.things:
            n_before = len(self.things)
            self.assertEqual(len(self.ss.things), n_before)
            thing_to_del = self.things.pop()
            self.ss.del_item(thing_to_del.key)
            n_after = n_before - 1
            self.assertEqual(len(self.things), n_after)
            self.assertEqual(len(self.ss.things), n_after)

    def test_add_item(self):
        ss = ScorableSet2()
        for _x in xrange(100):
            thing = MockScorableThing()
            self.assertEqual(len(ss.things), _x)
            ss.add_item(thing.key, thing)
            self.assertEqual(len(ss.things), _x + 1)
            self.assertTrue(thing.key in ss.things)
            self.assertTrue(thing in ss.things.values())

    def test_empty_set(self):
        ss = ScorableSet2()
        self.assertEqual(0, len(ss.things))
        self.assertRaises(EmptySetError, ss.next_key)
        self.assertRaises(EmptySetError, ss.next_item)

    def test_read_csv(self):
        self.assertRaises(ScorableSetError, self.ss._read_csv)

        self.ss.datafile = self.tmpfile
        d = {'x': 1, 'y': 2, 'z': 3}
        keys = list(d.keys())

        with open(self.ss.datafile, 'wb') as datafile:
            writer = csv.writer(datafile)
            writer.writerow(keys)
            row = [d[k] for k in keys]
            writer.writerow(row)

        read_csv = self.ss._read_csv()
        d_out = read_csv.pop(0)
        for k in keys:
            self.assertTrue(k in d_out)
            self.assertEqual(d[k], int(d_out[k]))

    def test_update_csv(self):
        self.ss._update_probabilities()
        # raise error if datafile is undefined
        self.assertRaises(ScorableSetError, self.ss.update_csv)

        self.ss.datafile = self.tmpfile
        self.assertFalse(os.path.exists(self.tmpfile))

        # make sure it can create a file from scratch
        self.ss.update_csv()
        self.assertTrue(os.path.exists(self.tmpfile))
        with open(self.ss.datafile, 'rb') as f:
            data = list(csv.DictReader(f))

        self.assertEqual(len(data), 1)
        for row in data:
            for k in self.ss.things.keys():
                self.assertTrue(k in row)

        # make sure it adds a second row
        self.ss.update_csv()
        with open(self.ss.datafile, 'rb') as f:
            data = list(csv.DictReader(f))

        self.assertEqual(len(data), 2)
        for row in data:
            for k in self.ss.things.keys():
                self.assertTrue(k in row)

        self.ss.update_csv()
        # we should be at 4 lines total now (1 header, 3 data)
        with open(self.ss.datafile, 'rb') as f:
            self.assertEqual(len(f.readlines()), 4)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
