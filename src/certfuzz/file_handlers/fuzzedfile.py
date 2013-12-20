'''
Created on Apr 12, 2013

@organization: cert.org
'''
from . import BasicFile

class FuzzedFile(BasicFile):
    '''
    Adds a derived_from field to BasicFile object
    '''
    def __init__(self, path, derived_from=None):
        BasicFile.__init__(self, path)
        self.derived_from = derived_from

    def to_FileDoc(self):
        from ..db.couchdb.datatypes.file_doc import FileDoc
        doc = FileDoc()
        doc = BasicFile.to_FileDoc(self, doc=doc)
        doc.derived_from_file_id = self.derived_from.to_FileDoc().id
        return doc
