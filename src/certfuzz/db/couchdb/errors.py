'''
Created on Mar 15, 2013

@organization: cert.org
'''
from .. import DbError

class CouchDbError(DbError):
    pass

class TestCaseDbError(CouchDbError):
    pass
