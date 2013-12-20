'''
Created on Oct 24, 2012

@organization: cert.org
'''
import unittest
import os
import stat

def is_executable(f):
    executable = stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
    st = os.stat(f)
    mode = st.st_mode
    return mode & executable

class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_tools_are_executable(self):
        my_dir = os.path.dirname(__file__)
        parent_dir = os.path.normpath(os.path.join(my_dir, '..', '..'))
        tools_dir = os.path.join(parent_dir, 'tools')
        self.assertTrue(os.path.exists(tools_dir), '%s not found' % tools_dir)
        tools = [x for x in os.listdir(tools_dir) if x.endswith('.py')]
        for tool in tools:
            #confirm tool is executable
            toolpath = os.path.join(tools_dir, tool)
            self.assertTrue(os.path.exists(toolpath), '%s does not exist' % tool)
            self.assertTrue(os.path.isfile(toolpath), '%s is not a file' % tool)
            self.assertTrue(is_executable(toolpath), '%s is not executable' % tool)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
