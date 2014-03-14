import collections
import logging
import zipfile

from certfuzz.fuzztools.filetools import check_zip_file, write_file
from certfuzz.fuzztools.filetools import exponential_backoff
from certfuzz.minimizer import Minimizer as MinimizerBase
from certfuzz.minimizer.errors import WindowsMinimizerError


logger = logging.getLogger(__name__)


class WindowsMinimizer(MinimizerBase):
    use_watchdog = False

    def __init__(self, cfg=None, crash=None, crash_dst_dir=None,
                 seedfile_as_target=False, bitwise=False, confidence=0.999,
                 logfile=None, tempdir=None, maxtime=3600, preferx=False,
                 keep_uniq_faddr=False, watchcpu=False):

        self.saved_arcinfo = None
        self.is_zipfile = check_zip_file(crash.fuzzedfile.path)

        MinimizerBase.__init__(self, cfg, crash, crash_dst_dir,
                               seedfile_as_target, bitwise, confidence,
                               logfile, tempdir, maxtime, preferx,
                               keep_uniq_faddr, watchcpu)

    def get_signature(self, dbg, backtracelevels):
        # get the basic signature
        crash_hash = MinimizerBase.get_signature(self, dbg, backtracelevels)
        if not crash_hash:
            self.signature = None
        else:
            crash_id_parts = [crash_hash]
            if self.crash.keep_uniq_faddr and hasattr(dbg, 'faddr'):
                crash_id_parts.append(dbg.faddr)
            self.signature = '.'.join(crash_id_parts)
        return self.signature

    def _read_fuzzed(self):
        '''
        returns the contents of the fuzzed file
        '''
        # store the files in memory
        if self.is_zipfile:  # work with zip file contents, not the container
            logger.debug('Working with a zip file')
            return self._readzip(self.crash.fuzzedfile.path)
        # otherwise just call the parent class method
        return MinimizerBase._read_fuzzed(self)

    def _read_seed(self):
        '''
        returns the contents of the seed file
        '''
        # we're either going to minimize to the seedfile, the metasploit
        # pattern, or a string of 'x's
        if self.is_zipfile and self.seedfile_as_target:
            return self._readzip(self.crash.seedfile.path)
        # otherwise just call the parent class method
        return MinimizerBase._read_seed(self)

    def _readzip(self, filepath):
        # If the seed is zip-based, fuzz the contents rather than the container
        logger.debug('Reading zip file: %s', filepath)
        tempzip = zipfile.ZipFile(filepath, 'r')

        '''
        get info on all the archived files and concatentate their contents
        into self.input
        '''
        self.saved_arcinfo = collections.OrderedDict()
        unzippedbytes = ''
        logger.debug('Reading files from zip...')
        for i in tempzip.namelist():
            data = tempzip.read(i)

            # save split indices and compression type for archival
            # reconstruction. Keeping the same compression types is
            # probably unnecessary since it's the content that matters

            self.saved_arcinfo[i] = (len(unzippedbytes), len(data),
                                        tempzip.getinfo(i).compress_type)
            unzippedbytes += data
        tempzip.close()
        return unzippedbytes

    @exponential_backoff
    def _safe_createzip(self, filepath):
        tempzip = zipfile.ZipFile(filepath, 'w')
        return tempzip

    def _writezip(self):
        '''rebuild the zip file and put it in self.fuzzed
        Note: We assume that the fuzzer has not changes the lengths
        of the archived files, otherwise we won't be able to properly
        split self.fuzzed
        '''
        if self.saved_arcinfo is None:
            raise WindowsMinimizerError('_readzip was not called')

        filedata = ''.join(self.newfuzzed)
        filepath = self.tempfile

        logger.debug('Creating zip with mutated contents.')
        tempzip = zipfile.ZipFile(filepath, 'w')

        '''
        reconstruct archived files, using the same compression scheme as
        the source
        '''
        for name, info in self.saved_arcinfo.iteritems():
            # write out fuzzed file
            if info[2] == 0 or info[2] == 8:
                # Python zipfile only supports compression types 0 and 8
                compressiontype = info[2]
            else:
                logger.warning('Compression type %s is not supported. Overriding', info[2])
                compressiontype = 8
            tempzip.writestr(name, str(filedata[info[0]:info[0] + info[1]]), compress_type=compressiontype)
        tempzip.close()

    def _write_file(self):
        if self.is_zipfile:
            self._writezip()
        else:
            write_file(''.join(self.newfuzzed), self.tempfile)
