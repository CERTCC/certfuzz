'''
Created on Feb 7, 2013

@organization: cert.org
'''
from ..android.api.activity_manager import ActivityManagerError
from ..android.api.errors import AdbCmdError
# from ..android.worker.defaults import TOMBSTONE_TIMEOUT, DBCFG, SF_CACHE_DIR
from ..android.worker.errors import WorkerError
from ..crash.android_testcase import AndroidTestCase
from ..db.couchdb.datatypes import FileDoc
from ..db.couchdb.db import TestCaseDb, put_file
from ..file_handlers.fuzzedfile import FuzzedFile
from ..file_handlers.seedfile import SeedFile
from ..fuzzers.bytemut import ByteMutFuzzer
from ..fuzztools.filetools import find_or_create_dir
from ..runners.android_runner import AndroidRunner
from ..runners import RunnerError
from .iteration_base import IterationBase2
from ..fuzzers import FuzzerExhaustedError

import logging
import os
import shutil
import tempfile


logger = logging.getLogger(__name__)


class EmuHandle(object):
    handle = None

emu = EmuHandle()


def _get_seedfile_by_id(tcdb, sf_dir, sfid):
    # find the doc record by id
    doc = FileDoc.load(tcdb.db, sfid)
    if doc is None:
        raise WorkerError('Seedfile not found in db, sfid=%s', sfid)

    sfpath = os.path.join(sf_dir, doc.filename)
    if not os.path.exists(sfpath):
        logger.info('Retrieving %s from db', doc.filename)
        # pull content from db, write to disk
        f = tcdb.db.get_attachment(doc, doc.filename)
        if f is None:
            raise WorkerError('Seedfile content not found in db, sfid=%s', sfid)

        logger.debug('...writing content to %s', sfpath)
        # make sure we have a dir to drop it in
        find_or_create_dir(sf_dir)
        with open(sfpath, 'wb') as out:
            out.write(f.read())
    else:
        logger.debug('Found cached seedfile at %s', sfpath)

    sf = SeedFile(sf_dir, sfpath)
    return sf


def do_iteration(iter_args):
    iter_args['emu_handle'] = emu.handle
    with AndroidIteration(**iter_args) as iteration:
        try:
            iteration.go()
        except FuzzerExhaustedError:
            # Some fuzzers run out of things to do. They should
            # raise a FuzzerExhaustedError when that happens.
            pass
    # TODO: pass something more useful than 'True'?  We just want to
    # know that it returns, so this may suffice for now
    # return iteration.result
    return True


class AndroidIteration(IterationBase2):
    def __init__(self, campaign_id=None, db_config=None, num=0, fuzzopts=None,
                 runopts=None, sf=None, emu_handle=None, sf_dir=None, intent=None):
        self.campaign_id = campaign_id
        self.db_config = db_config
        self.current_seed = num
        self.fuzzopts = fuzzopts
        self.runopts = runopts
        self.intent = intent
        self.sf_dir = sf_dir
        self.sf_id = sf
        self.fuzzer = ByteMutFuzzer
        self.runner = AndroidRunner
        self.emu_handle = emu_handle
        self.results = []
        self.minimizable = False
        self.tcdb = None
        self.sf = None
        self.tmpdir = None
        self.rng_seed = None
        self.crashes = []
        self.iteration_tmpdir_pfx = 'iteration_'

        logger.info('New task for campaign %s ', self.campaign_id)
        logger.debug('seedfile_id = %s', self.sf_id)
        logger.debug('iteration_num = %d', self.current_seed)
        logger.debug('fuzzopts = %s', self.fuzzopts)
        logger.debug('runopts = %s', self.runopts)

    def __enter__(self):
        logger.debug('Iteration %d start: %s', self.current_seed, self.sf_id)

        # create db conn
        host = self.db_config['host']
        port = self.db_config['port']
        username = self.db_config['username']
        password = self.db_config['password']
        db = self.db_config['dbname']
        self.tcdb = TestCaseDb(host, port, username, password, db)

        # get the seedfile, caching if needed
        self.sf = _get_seedfile_by_id(self.tcdb, self.sf_dir, self.sf_id)

        self.tmpdir = tempfile.mkdtemp(prefix='bff-fuzz-and-run-')

        return self

    def __exit__(self, etype, value, traceback):
        logger.debug('Iteration %d complete', self.current_seed)

        # remove tempdir
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        # clear db conn
        self.tcdb = None

        if etype:
            logger.warning('Iteration failed')
        if etype is AdbCmdError:
            logger.warning('ADB command failed')
        elif etype is RunnerError:
            logger.warning('Runner failed')
        elif etype is ActivityManagerError:
            logger.warning('Activity Manager failed')

    def _fuzz_and_run(self):
        # # FUZZ
        logger.info('...fuzzing')
        fuzz_opts = self.fuzzopts
        fuzz_args = self.sf, self.tmpdir, self.rng_seed, self.current_seed, fuzz_opts
        with self.fuzzer(*fuzz_args) as fuzzer:
            fuzzer.fuzz()
            self.fuzzed = True
#             self.r = fuzzer.range
#             if self.r:
#                 logger.info('Selected r: %s', self.r)

        fuzzed_file_full_path = fuzzer.output_file_path

        dst_basename = '%s-fuzzed%s' % (self.sf.root, self.sf.ext)
        dst_file = os.path.join('/', 'sdcard', dst_basename)

        # decide if we can minimize this case later
        # do this here (and not sooner) because the fuzzer could
        # decide at runtime whether it is or is not minimizable
        # TODO: add runoptions/minimize to config file
#         self.minimizable = fuzzer.is_minimizable and self.config['runoptions']['minimize']

        # # RUN
        logger.debug('...run')

        analysis_needed = False
        if self.runner:
            logger.info('...running %s', self.runner.__name__)
            run_args = {'handle': self.emu_handle,
                        'src_file': fuzzed_file_full_path,
                        'dst_file': dst_file,
                        'campaign_id': self.campaign_id,
                        'intent': self.intent,
                        'workingdir_base': self.tmpdir,
                        'options': self.runopts,
                        }
            with self.runner(**run_args) as runner:
                runner.run()
                analysis_needed = runner.saw_crash

        # is further analysis needed?
        logger.debug('...check for crash')
        if analysis_needed:
            logger.info('...analyzing')

            # put fuzzed file in db
            logger.info('...save fuzzed file to db')
            fuzzedfile = FuzzedFile(path=fuzzed_file_full_path, derived_from=self.sf)
            put_file(fuzzedfile, self.tcdb.db)

            # create testcase record
            logger.info('...create test case object')
            with AndroidTestCase(seedfile=self.sf,
                                 fuzzedfile=fuzzedfile,
                                 workdir_base=self.tmpdir,
                                 handle=self.emu_handle,
                                 input_dir=runner.result_dir,
                                 campaign_id=self.campaign_id,
                                 ) as testcase:
                logger.info('...store object to db')
                testcase.store(self.tcdb.db)
