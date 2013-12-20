'''
Created on Oct 15, 2012

@organization: cert.org
'''
import unittest
import os
import sys

mydir = os.path.dirname(os.path.abspath(__file__))
parentdir = os.path.abspath(os.path.join(mydir, '..'))

def find_tool_scripts(tools_dir):
    tool_scripts = [os.path.join(tools_dir, x) for x in os.listdir(tools_dir) if x.endswith('.py')]
    return tool_scripts

class Test(unittest.TestCase):

    def setUp(self):
        self.tools_dir = os.path.join(parentdir, 'tools')
        self.tool_scripts = find_tool_scripts(self.tools_dir)

    def tearDown(self):
        pass

    def test_all_linux_tools_are_executable(self):
        for script in self.tool_scripts:
            self.assertTrue(os.path.isfile(script), '%s is not a file' % script)
            self.assertTrue(os.access(script, os.X_OK), '%s is not executable' % script)

    def test_all_linux_tools_have_shebangs(self):
        for script in self.tool_scripts:
            with open(script, 'r') as f:
                first_line = f.readline()
                self.assertTrue(first_line.startswith('#!'), '%s has no shebang' % script)


    def testName(self):
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
