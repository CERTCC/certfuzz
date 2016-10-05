'''
Created on Mar 16, 2011

@organization: cert.org
'''
import hashlib
import os

from certfuzz.fuzztools.filetools import check_zip_content, read_bin_file


class BasicFile(object):
    '''
    Object to contain basic info about file: path, basename, dirname, len, md5
    '''

    def __init__(self, path):
        self.path = path
        (self.dirname, self.basename) = os.path.split(self.path)
        if '.' in self.basename:
            # Split on first '.' to retain multiple dotted extensions
            self.root = self.basename.split('.', 1)[0]
            ext = '.' + self.basename.split('.', 1)[1]
            # Get rid of any spaces in extension
            self.ext = ext.replace(' ', '')
        else:
            self.root = self.basename
            self.ext = ''

        self.len = None
        self.md5 = None
        self.bitlen = None
        self.is_zip = False

        self.refresh()

    def refresh(self):
        if self.exists():
            content = self.read()
            self.len = len(content)
            self.bitlen = 8 * self.len
            self.md5 = hashlib.md5(content).hexdigest()
            self.sha1 = hashlib.sha1(content).hexdigest()
            self.is_zip = check_zip_content(content)

    def read(self):
        '''
        Returns the contents of the file.
        '''
        return read_bin_file(self.path)

    def exists(self):
        return os.path.exists(self.path)

    def __repr__(self):
        return '%s' % self.__dict__

    def to_FileDoc(self, doc=None):
        from certfuzz.db.couchdb.datatypes.file_doc import FileDoc
        if doc is None:
            doc = FileDoc()
        doc.id = self.sha1
        doc.filename = self.basename
        doc.extension = self.ext
        doc.sha1 = self.sha1
        doc.size_in_bytes = self.len
        return doc
