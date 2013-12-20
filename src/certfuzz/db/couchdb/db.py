import logging
import os

try:
    import couchdb
    from .datatypes import FileDoc
except ImportError as e:
    pass

from .errors import TestCaseDbError

# Logging initialization
logger = logging.getLogger(__name__)

format_url = 'http://{}:{}/'.format

def put_file(basicfile, db):
    '''
    Checks for the existence of the file basicfile in the database. If not
    found, add it to the database. Return the corresponding db document.
    :param basicfile:
    '''

    logger.debug('Processing for insertion: %s', basicfile.path)
    if not basicfile.exists():
        logger.warning('Skipping non-existent file %s', basicfile.path)
        return

    # is it in the db already?
    doc = FileDoc.load(db, basicfile.sha1)
    if doc is not None:
        logger.info('File %s already in db', basicfile.path)
        return

    # new file...
    doc = basicfile.to_FileDoc()

    # put it in the db
    doc.store(db)

    # attach the content
    logger.info('Uploading %s to db', basicfile.path)
    with open(basicfile.path, 'rb') as fd:
        db.put_attachment(doc, fd, filename=basicfile.basename)

class TestCaseDb():

    '''
    This class is a wrapper for the CouchDB client API.  It creates a connection to the database
    server and stores a handle to a Database object (self.db) which is used for
    directly interacting with the CouchDB database.  This class also contains helper methods
    for common database interactions.
    '''
    def __init__(self, host='localhost', port=5984, username=None,
                 password=None, dbname='bff', force_create=True):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.db_name = dbname
        self.force_create = force_create

        self.connection_string = format_url(self.host, self.port)

        self.server = None
        self.db = None

        self.connect()

    def _check_dbname(self):
        if self.db_name is None:
            raise TestCaseDbError('db_name is not defined')
        # couchdb requires lowercase db names
        self.db_name = self.db_name.lower()

    def _set_server(self):
        logger.debug('Connecting: %s', self.connection_string)
        self.server = couchdb.Server(self.connection_string)
        if self.username is not None and self.password is not None:
            logger.debug('Setting username/password for db connection')
            self.server.resource.credentials = (self.username, self.password)

    def _set_db(self):
        self._check_dbname()
        # Check if DB exists. If not, create it.
        logger.debug('Checking to see if we need to create db %s', self.db_name)
        if not self.db_name in self.server:
            if self.force_create:
                self.create()
            else:
                raise TestCaseDbError('The specified db \'%s\' does not exist' % self.db_name)
        logger.debug('Setting db to %s', self.db_name)
        self.db = self.server[self.db_name]

    def connect(self):
        self._set_server()
        self._set_db()

    def create(self):
        '''
        Creates a database with the given name on the server specified during the TestCaseDb
        object's initialization.
        '''
        logger.debug('Creating db %s', self.db_name)
        self._check_dbname()

        try:
            self.server.create(self.db_name)
            logger.debug("Created database with name %s", self.db_name)
        except couchdb.http.PreconditionFailed:
            logger.debug('Skipping create on %s: db exists' % self.db_name)

    def destroy(self, reason='unspecified'):
        '''
        DANGEROUS: Destroys the database and all of its associated data, optionally allowing
        for a reason to be given and logged.
        '''
        del self.server[self.db_name]
        logger.warning("Database '" + self.db_name + "' destroyed with reason: " + reason)

    def wipe(self, reason='unspecified'):
        '''
        Wipes a database by deleting it and then recreating it.
        '''
        logger.info("Database is being wiped with reason: " + reason)
        self.destroy(reason)
        self.create(self.db_name)

    def is_connected(self):
        '''
        Returns True if the connection to the database is established, and False if it is not.

        @rtype: boolean
        '''
        if self.db_name in self.server:
            return True
        else:
            return False

    def info(self):
        '''
        Returns a dictionary containing information about the database.

        @rtype: dictionary of strings
        '''
        if self.is_connected():
            return self.db.info()
        else:
            return None

    def print_dump(self):
        '''
        Prints every document in the database.  Useful for testing.
        '''
        if self.is_connected():
            for x in self.db:
                print str(type(self.db[x]))
                print self.db[x]
        else:
            return None

    def add_docs(self, docs, campaign_id):
        for doc in docs:
            self.add(doc, campaign_id)

    def add(self, doc):
        '''
        Takes a Doc object (crashdb.data.db_structs.Doc) which consists of a Document (couchdb.mapping.Document)
        as 'document' and a list of associated files as 'attachments'. The document is first inserted into
        the database, and then attachments are subsequently attached to it and inserted one at a time.
        '''
        try:
            document = doc.document.store(self.db)
            logger.debug('Adding: ' + str(document) + '\n')
            for attachment in doc.attachments:
                a = open(attachment, 'rb').read()
                self.db.put_attachment(document, a, filename=os.path.basename(attachment))
        except couchdb.ResourceConflict:
            # Log it; may not be entirely necessary since it's just telling us that the document is already in the DB
            logging.error('A couchdb.ResourceConflict was raised for the following document with id '
                          + document._id + ': \n\t' + str(doc))
        return doc.document['_id']

    def bulk_insert(self, docs):
        _list = [doc.document for doc in docs]

        ids = self.db.update(_list)

        counter = 0
        for _id in ids:
            for attachment in docs[counter].attachments:
                a = open(attachment, 'rb').read()
                self.db.put_attachment(self.db[_id[1]], a, filename=os.path.basename(attachment))
            counter += 1

        return ids

    def get(self, doc_id):
        return self.db[doc_id]

