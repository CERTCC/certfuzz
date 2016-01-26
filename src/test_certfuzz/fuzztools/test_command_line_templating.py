'''
Created on Jan 26, 2016

@author: adh
'''
import unittest
import certfuzz.fuzztools.command_line_templating as clt
import string


class Test(unittest.TestCase):


    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_get_command_args_list(self):
        cmd = 'program arg1 arg2 $SEEDFILE arg3 arg4'
        cmd_template = string.Template(cmd)
        infile = 'foobar'
        
        result=clt.get_command_args_list(cmd_template,infile)
        self.assertEqual(2, len(result))
        
        (as_string,as_list) = result
        
        for substring in ['program','arg1','arg2','arg3','arg4','foobar']:
            self.assertTrue(substring in as_string)
            self.assertTrue(substring in as_list)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()