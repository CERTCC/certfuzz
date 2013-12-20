# '''
# Created on Jan 17, 2013
#
# @organization: cert.org
# '''
# from .defaults import TOMBSTONE_TIMEOUT, DBCFG, SF_CACHE_DIR
# from ..api.activity_manager import ActivityManagerError
# from ..api.errors import AdbCmdError
# from ..api.log_helper import pfunc
# from ..celery import celery
# from ...android.worker.errors import WorkerError
# from ...crash.android_testcase import AndroidTestCase
# from ...db.couchdb.datatypes import FileDoc
# from ...db.couchdb.db import TestCaseDb
# from ...db.couchdb.db import put_file
# from ...file_handlers.fuzzedfile import FuzzedFile
# # from ...file_handlers.basicfile import BasicFile
# from ...file_handlers.seedfile import SeedFile
# from ...file_handlers.tempdir import TempDir
# from ...fuzztools.filetools import find_or_create_dir
# from ...runners import AndroidRunner, RunnerError
# import logging
# import os


class EmuHandle(object):
    handle = None

emu = EmuHandle()
#
# logger = logging.getLogger(__name__)
#
# # use default dbcfg from yaml file
# dbcfg = DBCFG
# sf_dir = SF_CACHE_DIR
#
# def _get_seedfile_by_id(tcdb, sfid):
#     # find the doc record by id
#     doc = FileDoc.load(tcdb.db, sfid)
#     if doc is None:
#         raise WorkerError('Seedfile not found in db, sfid=%s', sfid)
#
#     sfpath = os.path.join(sf_dir, doc.filename)
#     if not os.path.exists(sfpath):
#         logger.info('Retrieving %s from db', doc.filename)
#         # pull content from db, write to disk
#         f = tcdb.db.get_attachment(doc, doc.filename)
#         if f is None:
#             raise WorkerError('Seedfile content not found in db, sfid=%s', sfid)
#
#         logger.debug('...writing content to %s', sfpath)
#         # make sure we have a dir to drop it in
#         find_or_create_dir(sf_dir)
#         with open(sfpath, 'wb') as out:
#             out.write(f.read())
#     else:
#         logger.debug('Found cached seedfile at %s', sfpath)
#
#     sf = SeedFile(sf_dir, sfpath)
#     return sf
#
# @celery.task
# def fuzz_and_run(campaign_id, seedfile_id, iteration_num, rng_seed, fuzzopts, runopts):
#     logger.info('New task for campaign %s ', campaign_id)
#     logger.debug('seedfile_id = %s', seedfile_id)
#     logger.debug('iteration_num = %d', iteration_num)
#     logger.debug('rng_seed = %s', rng_seed)
#     logger.debug('fuzzopts = %s', fuzzopts)
#     logger.debug('runopts = %s', runopts)
#
#     tcdb = TestCaseDb(**dbcfg)
#
#     # get the seedfile, caching if needed
#     sfobj = _get_seedfile_by_id(tcdb, seedfile_id)
#
#     with TempDir(prefix='bff-fuzz-and-run-') as tmpdir:
#         # # FUZZ
#         logger.debug('...fuzz')
#         src_file = fuzz(sfobj, tmpdir, rng_seed,
#                         iteration_num, fuzzopts)
#
#         dst_basename = '%s-fuzzed%s' % (sfobj.root, sfobj.ext)
#         dst_file = os.path.join('/', 'sdcard', dst_basename)
#
#         # # RUN
#         logger.debug('...run')
#         if not runopts.get('runtimeout'):
#             runopts['runtimeout'] = TOMBSTONE_TIMEOUT
#
#         try:
#             with AndroidRunner(handle=emu.handle,
#                                src_file=src_file,
#                                dst_file=dst_file,
#                                campaign_id=campaign_id,
#                                intent=runopts['intent'],
#                                workingdir_base=tmpdir,
#                                options=runopts,
#                                ) as runner:
#                 runner.run()
#         except (AdbCmdError, RunnerError, ActivityManagerError) as e:
#             # this is fatal to this task, so requeue it for somebody else to try
#             logger.warning('Runner failed, requeuing task: %s', e)
#             raise fuzz_and_run.retry(exc=e)
#
#         # # CHECK FOR CRASH
#         logger.debug('...check for crash')
#         if runner.saw_crash:
#             # put fuzzed file in db
#             logger.info('...saw crash')
#             fuzzedfile = FuzzedFile(path=src_file, derived_from=sfobj)
#             put_file(fuzzedfile, tcdb.db)
#
#             # create testcase record
#             logger.info('...create test case object')
#             with AndroidTestCase(seedfile=sfobj,
#                                  fuzzedfile=fuzzedfile,
#                                  workdir_base=tmpdir,
#                                  handle=emu.handle,
#                                  input_dir=runner.result_dir,
#                                  campaign_id=campaign_id,
#                                  ) as testcase:
#                 logger.info('...store object to db')
#                 testcase.store(tcdb.db)
#
#
# @pfunc(logger=logger)
# def fuzz(sfobj, outdir_base, rng_seed, iteration, options):
#     # TODO: this should move to certfuzz.fuzzers
#     from certfuzz.fuzzers.bytemut import ByteMutFuzzer
#
#     if options is None:
#         options = {}
#
#     with ByteMutFuzzer(seedfile_obj=sfobj,
#                        outdir_base=outdir_base,
#                        rng_seed=rng_seed,
#                        iteration=iteration,
#                        options=options,) as fuzzer:
# # TODO: assuming this works with a SeedFile object you don't need the fake RF
# #         class RFdummy(object):
# #             def next_item(self):
# #                 class Rdummy(object):
# #                     min = 0.0
# #                     max = 1.0
# #                 return Rdummy()
# #         fuzzer.sf.rangefinder = RFdummy()
#         fuzzer.fuzz()
#     return fuzzer.output_file_path
