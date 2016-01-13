'''
Created on Jan 13, 2016

@author: adh
'''
import unittest
import certfuzz.reporters.testcase_logger
from test_certfuzz.mocks import MockTestcase

class Test(unittest.TestCase):


    def setUp(self):
        pass


    def tearDown(self):
        pass


    def test_go(self):
        import logging
        import io

        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

        log_capture_string = io.StringIO()
        hdlr = logging.StreamHandler(log_capture_string)
        hdlr.setLevel(logging.DEBUG)

        logger.addHandler(hdlr)

        tc = MockTestcase()
        r = certfuzz.reporters.testcase_logger.TestcaseLoggerReporter(tc)
        with r:
            r.go()

        log_contents = log_capture_string.getvalue()

        log_capture_string.close()

        for x in ['seen in', 'at seed', 'range', 'outfile', 'PC']:
            self.assertTrue(x in log_contents, '"{}" not in log'.format(x))


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
