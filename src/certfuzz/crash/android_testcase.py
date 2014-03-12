'''
Created on Apr 11, 2013

@organization: cert.org
'''
import logging
import os

from certfuzz.android.api import AdbCmd
from certfuzz.android.api.log_helper import pfunc
from certfuzz.crash import TestCaseBase
from certfuzz.file_handlers.basicfile import BasicFile


logger = logging.getLogger(__name__)


class AndroidTestCase(TestCaseBase):
    '''
    classdocs
    '''
    _tmp_pfx = 'BFF_android_testcase_'

    def __init__(self, seedfile, fuzzedfile, workdir_base, handle, input_dir,
                 campaign_id=None):
        '''
        Constructor
        '''
        TestCaseBase.__init__(self, seedfile, fuzzedfile, workdir_base)
        self.handle = handle
        self.input_dir = input_dir
        self.campaign_id = campaign_id
        self._keep_local_copy = True
        self.attachments = set()

    def __enter__(self):
        TestCaseBase.__enter__(self)
        self.collect_data()
        return self

    @pfunc(logger=logger)
    def collect_data(self):
        # if you got here, it's because there was a tombstone
        logger.info('Getting bugreport')

        with AdbCmd(handle=self.handle) as adbcmd:
            adbcmd.bugreport()
            bugreport_result = adbcmd

        if bugreport_result is not None:
            self._write_bugreport(bugreport_result)

    @pfunc(logger=logger)
    def _write_bugreport(self, bugreport):
        '''
        Looks for bugreport.stdout or bugreport.stderr
        :param bugreport:
        '''
        outfile = 'bugreport-{}.txt'.format
        for key in ['stdout', 'stderr']:
            try:
                value = getattr(bugreport, key)
            except AttributeError:
                # go to next key if bugreport doesn't have this one
                continue

            if not value:
                # go to next key if value is empty or None
                continue

            of = os.path.join(self.working_dir, outfile(key))
            try:
                with open(of, 'w') as f:
                    logger.debug('write to %s', of)
                    f.write(value)
                self.attachments.add(of)
            except EnvironmentError as e:
                # parent of IOError, OSError, and WindowsError
                # not fatal to the task, we just didn't get a bugreport
                logger.warning('Write bugreport failed: %s', e)

    @pfunc(logger=logger)
    def _store_attachments(self, doc, db):
        for attachment_path in self.attachments:
            f = BasicFile(attachment_path)
            logger.debug('Attaching %s to record %s', f.path, doc.id)
            with open(f.path, 'rb') as fp:
                db.put_attachment(doc, fp, filename=f.basename)

    @pfunc(logger=logger)
    def store(self, db):
        '''
        Convert the data in this object to a couchdb record & send it to db
        :param db:
        '''
        doc = self.to_TestCaseDoc()
        logger.debug('Store %s to db', doc.id)
        doc.store(db)
        self._store_attachments(doc, db)

    @pfunc(logger=logger)
    def to_TestCaseDoc(self):
        logger.debug('Convert test case to db doc')
        doc = TestCaseBase.to_TestCaseDoc(self)
        doc.campaign_id = self.campaign_id
        return doc
