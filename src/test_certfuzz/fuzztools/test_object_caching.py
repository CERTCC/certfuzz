import pickle
import tempfile
import os
'''
Created on Sep 27, 2011

@organization: cert.org
'''

import unittest
import certfuzz.fuzztools.object_caching as object_caching

class Mock(object):
    pass

class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_load_obj_from_file(self):
        (fd, filename) = tempfile.mkstemp()
        os.close(fd)

        with open(filename, 'w') as f:
            foo = Mock()
            foo.bar = 1
            foo.baz = 2
            pickle.dump(foo, f)

        qux = object_caching.load_obj_from_file(filename)
        self.assertEqual(1, qux.bar)
        self.assertEqual(2, qux.baz)

        os.remove(filename)
        self.assertFalse(os.path.exists(filename))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
