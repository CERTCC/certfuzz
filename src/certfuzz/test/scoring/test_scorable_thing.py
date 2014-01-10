'''
Created on Apr 10, 2012

@organization: cert.org
'''
import unittest
from certfuzz.scoring.scorable_thing import ScorableThing


class Test(unittest.TestCase):

    def setUp(self):
        self.thing1 = ScorableThing()
        self.thing2 = ScorableThing(key='Thing2')

    def tearDown(self):
        pass

    def test_init(self):
        self.assertTrue(self.thing1.key.startswith('scorable_thing_'))
        self.assertEqual(self.thing2.key, 'Thing2')

        self.assertEqual(0, self.thing1.successes)
        self.assertEqual(0, self.thing1.tries)
        self.assertEqual(0.5, self.thing1.probability)

    def test_repr(self):
        self.assertEqual(self.thing2.__repr__(), 'Thing2')

    def test_record_failure(self):
        self.assertEqual(0, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)
        self.thing1.record_failure()
        self.assertEqual(1, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)
        # with tries as keyword
        self.thing1.record_failure(tries=3)
        self.assertEqual(4, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)
        # with tries, no keyword
        self.thing1.record_failure(32)
        self.assertEqual(36, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)

    def test_record_success(self):
        self.assertEqual(0, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)
        self.thing1.record_success('a')
        self.assertEqual(1, self.thing1.tries)
        self.assertEqual(1, self.thing1.successes)
        # with tries as keyword
        self.thing1.record_success('b', tries=3)
        self.assertEqual(4, self.thing1.tries)
        self.assertEqual(2, self.thing1.successes)
        # with tries, no keyword
        self.thing1.record_success('c', 32)
        self.assertEqual(36, self.thing1.tries)
        self.assertEqual(3, self.thing1.successes)
        # repeat
        self.thing1.record_success('c')
        self.assertEqual(37, self.thing1.tries)
        self.assertEqual(3, self.thing1.successes)
        self.thing1.record_success('a', 3)
        self.assertEqual(40, self.thing1.tries)
        self.assertEqual(3, self.thing1.successes)

    def test_record_result(self):
        self.assertEqual(0, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)
        self.thing1.record_result(successes=0, tries=0)
        self.assertEqual(0, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)

        self.thing1.record_result(successes=0, tries=1)
        self.assertEqual(1, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)

        self.thing1.record_result(successes=1, tries=1)
        self.assertEqual(2, self.thing1.tries)
        self.assertEqual(1, self.thing1.successes)

    def test_update(self):
        self.assertEqual(1, self.thing1.a)
        self.assertEqual(1, self.thing1.b)
        self.assertEqual(0.5, self.thing1.probability)
        self.thing1.update(1, 1)
        self.assertEqual(2, self.thing1.a)
        self.assertEqual(1, self.thing1.b)
        self.assertAlmostEqual(0.667, self.thing1.probability, places=3)
        self.thing1.update(1, 10)
        self.assertEqual(3, self.thing1.a)
        self.assertEqual(10, self.thing1.b)
        self.assertAlmostEqual(0.231, self.thing1.probability, places=3)

    def test_getstate_is_picklable(self):
        # getstate should return picklable thing
        import cPickle
        try:
            cPickle.dumps(self.thing1.__getstate__())
        except:
            self.fail('Unable to pickle __getstate__ result')

    def test_getstate_returns_dict(self):
        self.assertEqual(dict, type(self.thing1.__getstate__()))
        self.assertEqual(self.thing1.__getstate__(), self.thing1.__dict__)

    def test_to_json(self):
        try:
            self.assertEqual(str, type(self.thing1.to_json()))
        except Exception, e:
            self.fail('json.dumps failed: %s' % e)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
