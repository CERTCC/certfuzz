'''
Created on Oct 29, 2014

@organization: cert.org
'''
import unittest
import tempfile
import shutil
import certfuzz.tc_pipeline.tc_pipeline_base
from test_certfuzz.mocks import MockMinimizer


class TCPL_Impl(certfuzz.tc_pipeline.tc_pipeline_base.TestCasePipelineBase):
    _minimizer_cls = MockMinimizer

    def _setup_analyzers(self):
        pass

    def _minimize(self, testcase):
        pass

    def _post_minimize(self, testcase):
#         certfuzz.tc_pipeline.tc_pipeline_base.TestCasePipelineBase._post_minimize(self, testcase)
        pass

    def _verify(self, testcase):
        pass

    def _report(self, testcase):
        pass


class Test(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_abstract_class(self):
        cls = certfuzz.tc_pipeline.tc_pipeline_base.TestCasePipelineBase

        # should fail since we haven't implemented the abc methods
        self.assertRaises(TypeError, cls)

        try:
            TCPL_Impl(outdir=self.tmpdir)
        except TypeError as e:
            self.fail('Dummy implementation class failed to instantiate: {}'.format(e))

    def test_pipeline_coroutines(self):
        tcpl = TCPL_Impl(outdir=self.tmpdir)
        results = []

        def func(tc):
            results.append(tc)

        class MockTestCase(object):
            should_proceed_with_analysis = True
            def get_logger(self):
                pass

        tcpl._verify = func
        tcpl._minimize = func
        tcpl._analyze = func
        tcpl._report = func
        funcs2check = [tcpl.verify,
                       tcpl.minimize,
                       tcpl.analyze,
                       tcpl.report,
                       ]

        tc = MockTestCase()
        # if this test works, results will get [0,1,2,...]
        # because each of the above functions will call
        # its corresponding _function which will append
        # i to results
        for i, plfunc in enumerate(funcs2check):
            # setup the pipeline coroutine
            testfunc = plfunc()
            self.assertEqual(i, len(results))
            testfunc.send(tc)
            self.assertEqual(i + 1, len(results))
            self.assertEqual(tc, results[-1])

    def test_analyze(self):
        class TCPL_Impl2(TCPL_Impl):
            def _analyze(self, testcase):
                certfuzz.tc_pipeline.tc_pipeline_base.TestCasePipelineBase._analyze(self, testcase)

        tcpl = TCPL_Impl2(outdir=self.tmpdir)

        class MockTestCase(object):
            pass

        analyzer_count = []

        class MockAnalyzer(object):
            def __init__(self, *args, **kwargs):
                pass

            def go(self):
                analyzer_count.append(1)

        touch_watchdog_call_count = []

        def inc_cc():
            touch_watchdog_call_count.append(1)

        # monkey patch touch_watchdog_file
        certfuzz.tc_pipeline.tc_pipeline_base.touch_watchdog_file = inc_cc

        tc = MockTestCase()
        tcpl.analyzer_classes = [MockAnalyzer for _ in range(5)]
        tcpl._analyze(tc)
        self.assertEqual(5, sum(analyzer_count))
        self.assertEqual(5, sum(touch_watchdog_call_count))


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
