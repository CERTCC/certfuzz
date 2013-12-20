from certfuzz.fuzztools.watchdog import WatchDog

'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest

class Test(unittest.TestCase):

    def setUp(self):
        self.w = WatchDog("/tmp/foo", 1234567890)

    def tearDown(self):
        pass

    def test_get_watchdog_timeout_cmdline(self):
        expected = 'sudo sh -c "echo file=/tmp/foo > /etc/watchdog.conf && echo change=1234567890 >> /etc/watchdog.conf && /etc/init.d/watchdog restart"'
        self.assertEqual(self.w._get_cmdline(), expected)

    def test_go(self):
        # cannot test directly, see test_get_watchdog_timeout_cmdline()
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
