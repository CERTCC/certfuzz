'''
Created on Feb 24, 2016

@author: adh
'''
import unittest


class Test(unittest.TestCase):


    def setUp(self):
        pass


    def tearDown(self):
        pass


    def test_confirm_api(self):
        import certfuzz.analyzers.drillresults as dr

        # we basically just need to make sure that the platform-specific
        # drillresults classes are imported in to the package namespace
        from certfuzz.analyzers.drillresults.drillresults import LinuxDrillResults, WindowsDrillResults, DrillResults

        for cls in (LinuxDrillResults, WindowsDrillResults, DrillResults):
            self.assertTrue(cls.__name__ in dr.__dict__)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
