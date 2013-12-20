'''
Created on Mar 15, 2013

@organization: cert.org
'''
try:
    from couchdb.mapping import TextField, Document, IntegerField
except ImportError as e:
    pass

class TestCaseDoc(Document):
    doctype = TextField(default='TestCase')
    campaign_id = TextField()
    crash_signature = TextField()
    seed_file = TextField()  # _id of the File document containing the seed
    fuzzed_file = TextField()  # _id of the File document containing the fuzzed file
    minimized_file = TextField()  # _id of the File document containing the minimized file
    # Attachments: Any files that do not have the same extension as the associated seed file
    bitwise_hd = IntegerField()
    bytewise_hd = IntegerField()
