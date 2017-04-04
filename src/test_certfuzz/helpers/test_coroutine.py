'''
Created on Oct 29, 2014

@organization: cert.org
'''
import unittest
import certfuzz.helpers.coroutine


class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_coroutine(self):
        results = []

        # set up a simple function that multiplies
        # the values sent to it and appends it to
        # a list
        @certfuzz.helpers.coroutine.coroutine
        def func(results):
            while True:
                x = (yield)
                results.append(2 * x)

        # set up the coroutine
        c = func(results)

        # confirm that results has the right size and values
        for i in range(100):
            self.assertEqual(i, len(results))
            c.send(i)
            self.assertEqual(i + 1, len(results))
            self.assertEqual(i * 2, results[-1])


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
