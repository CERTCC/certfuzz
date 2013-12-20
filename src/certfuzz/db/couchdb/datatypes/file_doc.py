'''
Created on Mar 15, 2013

@organization: cert.org
'''
try:
    from couchdb.mapping import TextField, IntegerField, Document
except ImportError as e:
    pass

class FileDoc(Document):
    doctype = TextField(default='File')
    filename = TextField()
    extension = TextField()
    sha1 = TextField()
    size_in_bytes = IntegerField()
    derived_from_file_id = TextField()
    # Attachment: file data
