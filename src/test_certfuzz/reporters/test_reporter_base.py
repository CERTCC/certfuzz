'''
Created on Jan 13, 2016

@author: adh
'''
import unittest
import certfuzz.reporters.reporter_base
from certfuzz.reporters.reporter_base import ReporterBase

class Test(unittest.TestCase):


    def setUp(self):
        pass


    def tearDown(self):
        pass


    def testAbcMethods(self):
        self.assertRaises(TypeError, ReporterBase)

        class Fail(ReporterBase):
            pass

        self.assertRaises(TypeError, Fail)

        class Pass(ReporterBase):
            def go(self):
                pass

        Pass('dummytc')

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
