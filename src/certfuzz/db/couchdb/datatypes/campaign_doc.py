'''
Created on Mar 15, 2013

@organization: cert.org
'''
try:
    from couchdb.mapping import TextField, Document, DictField, DateTimeField
except ImportError as e:
    pass

from datetime import datetime

class CampaignDoc(Document):
    doctype = TextField(default='Campaign')
    campaign_type = TextField(default='Base')
    config = DictField()
    added = DateTimeField(default=datetime.now())

class AndroidCampaignDoc(CampaignDoc):
    campaign_type = TextField(default='Android')
    fuzzopts = DictField()
    runopts = DictField()

class BFFCampaignDoc(CampaignDoc):
    campaign_type = TextField(default='BFF')
    fuzzer = TextField()
    command = TextField()
