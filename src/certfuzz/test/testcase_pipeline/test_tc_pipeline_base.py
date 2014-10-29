'''
Created on Oct 29, 2014

@organization: cert.org
'''
import unittest
import certfuzz.testcase_pipeline.tc_pipeline_base


class TCPL_Impl(certfuzz.testcase_pipeline.tc_pipeline_base.TestCasePipelineBase):
    def _setup_analyzers(self):
        pass

    def _minimize(self):
        pass

    def _verify(self):
        pass

    def _analyze(self):
        pass

    def _report(self):
        pass


class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_abstract_class(self):
        cls = certfuzz.testcase_pipeline.tc_pipeline_base.TestCasePipelineBase

        # should fail since we haven't implemented the abc methods
        self.assertRaises(TypeError, cls)

        try:
            TCPL_Impl()
        except TypeError as e:
            self.fail('Dummy implementation class failed to instantiate: {}'.format(e))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
