'''
Created on Mar 18, 2013

@organization: cert.org
'''
import unittest
from certfuzz.db.couchdb import db

class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_format_url(self):
        import itertools
        for host, port in itertools.product(['foo', 'bar', 'baz', 'quux'], range(20)):
            self.assertEqual('http://' + host + ':' + str(port) + '/', db.format_url(host, port))

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
