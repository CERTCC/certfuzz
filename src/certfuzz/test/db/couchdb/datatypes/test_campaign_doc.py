# '''
# Created on Mar 15, 2013
#
# @organization: cert.org
# '''
# import unittest
# from certfuzz.db.couchdb.datatypes import campaign_doc
#
# class Test(unittest.TestCase):
#
#     def setUp(self):
#         self.doc = campaign_doc.CampaignDoc()
#
#     def tearDown(self):
#         pass
#
#     def test_campaign_doc(self):
#         print dir(self.doc)
#
#         try:
#             from couchdb.mapping import Document
#             self.assertIsInstance(self.doc, Document)
#         except ImportError:
#             pass
#
#         self.assertEqual('Campaign', self.doc.doctype)
#         for field in ['doctype', 'campaign_type', 'config', 'added']:
#             self.assertTrue(hasattr(self.doc, field))
#
# if __name__ == "__main__":
#     # import sys;sys.argv = ['', 'Test.testName']
#     unittest.main()
