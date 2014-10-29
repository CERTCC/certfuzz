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

    def test_pipeline_coroutines(self):
        tcpl = TCPL_Impl()
        results = []

        def func(tc):
            results.append(tc)

        tcpl._verify = func
        tcpl._minimize = func
        tcpl._analyze = func
        tcpl._report = func
        funcs2check = [tcpl.verify,
                       tcpl.minimize,
                       tcpl.analyze,
                       tcpl.report,
                       ]

        # if this test works, results will get [0,1,2,...]
        # because each of the above functions will call
        # its corresponding _function which will append
        # i to results
        for i, plfunc in enumerate(funcs2check):
            #setup the pipeline coroutine
            testfunc = plfunc()
            self.assertEqual(i, len(results))
            testfunc.send(i)
            self.assertEqual(i + 1, len(results))
            self.assertEqual(i, results[-1])

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
