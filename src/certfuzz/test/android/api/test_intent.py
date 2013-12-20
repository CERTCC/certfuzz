# '''
# Created on Feb 1, 2013
#
# @organization: cert.org
# '''
# import unittest
# import certfuzz.android.api.intent
# from certfuzz.android.api.intent import _attribute_to_option
#
# class Test(unittest.TestCase):
#
#     def setUp(self):
#         self.intent = certfuzz.android.api.intent.Intent()
#
#     def tearDown(self):
#         pass
#
#     def test_as_args(self):
#         for attribute in ('action', 'data_uri', 'mime_type'):
#             self.assertTrue(hasattr(self.intent, attribute))
#             setattr(self.intent, attribute, attribute)
#             self.assertIn(attribute, self.intent.as_args())
#
#         for opt in ('-a', '-d', '-t'):
#             self.assertIn(opt, self.intent.as_args())
#
#         for attribute in certfuzz.android.api.intent._bool_attrs:
#             self.assertTrue(hasattr(self.intent, attribute))
#             self.assertFalse(getattr(self.intent, attribute))
#             self.assertNotIn(attribute, self.intent.as_args())
#             setattr(self.intent, attribute, True)
#             self.assertTrue(getattr(self.intent, attribute))
#
#             self.assertIn(_attribute_to_option(attribute),
#                            self.intent.as_args())
#
#     def test_attribute_to_option(self):
#         for x in xrange(30):
#             in_str = '_'.join('a' * x)
#             out_str = '--' + '-'.join('a' * x)
#             self.assertEqual(out_str, _attribute_to_option(in_str))
#
# if __name__ == "__main__":
#     # import sys;sys.argv = ['', 'Test.testName']
#     unittest.main()
