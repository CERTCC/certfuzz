'''
Created on Feb 3, 2012

@organization: cert.org
'''
import os
import logging
import StringIO
import zipfile
import collections

from ..fuzztools.hamming import bytewise_hd, bitwise_hd
from ..fuzztools.filetools import write_file
from ..fuzztools.filetools import find_or_create_dir
from ..helpers import log_object
from .errors import FuzzerInputMatchesOutputError


MAXDEPTH = 3
SLEEPTIMER = 0.5
BACKOFF_FACTOR = 2

logger = logging.getLogger(__name__)


def logerror(func, path, excinfo):
    logger.warning('%s failed to remove %s: %s', func, path, excinfo)


def is_fuzzable(x, exclude_list):
    '''
    Returns true if x is not in any range in range_list
    :param x:
    :param range_list:
    '''
    if exclude_list is None:
        exclude_list = []

    for (low, high) in exclude_list:
        if low <= x <= high:
            return False
    return True


class Fuzzer(object):
    '''
    The Fuzzer class is intended to be used as the parent class for actual
    fuzzer implementations. It should be implemented in a runtime context using
    the 'with' construct:

    with Fuzzer(*args) as fuzzer:
        fuzzer.go()
    '''
    # Not all fuzzers are minimizable. Default to false, and those
    # child classes that are can set it themselves
    is_minimizable = False

    def __init__(self, seedfile_obj, outdir_base, rng_seed, iteration, options):
        '''
        Parameters get converted to attributes.
        @param local_seed_path:
        @param fuzz_output_path:
        @param rng_seed:
        @param iteration:
        @param options:
        '''
        logger.debug('Initialize Fuzzer')
        self.sf = seedfile_obj
        # TODO: rename tmpdir -> working_dir
        self.tmpdir = outdir_base
        self.rng_seed = rng_seed
        self.iteration = iteration
        self.options = options

        # set up some file name related attributes
        self.basename_fuzzed = '%s-%d%s' % (self.sf.root, self.iteration, self.sf.ext)
        self.output_file_path = os.path.join(self.tmpdir, self.basename_fuzzed)

        self.input = None
        self.fuzzed = None
        self.fuzzed_changes_input = True
        # Not all fuzzers use rangefinder. Default to None and
        # set it in child classes for those that do
        self.range = None
        self.saved_arcinfo = collections.OrderedDict()

        self._parse_options()

        log_object(self, logger)

    def __enter__(self):
        find_or_create_dir(self.tmpdir)
        self.input = bytearray(self.sf.read())
        self._validate()
        return self

    def __exit__(self, etype, value, traceback):
        pass

    def write_fuzzed(self, outdir=None):
        if outdir:
            outfile = os.path.join(outdir, self.basename_fuzzed)
        else:
            outfile = self.output_file_path

        if self.fuzzed:
            write_file(self.fuzzed, outfile)
        self.output_file_path = outfile
        return os.path.exists(outfile)

    def fuzz(self):
        if not self.fuzzed:
            self._prefuzz()
            self._fuzz()
            self._postfuzz()
#            if self.fuzzed_changes_input:
#                self._verify()

        return self.write_fuzzed()

#    def _verify(self):
#        '''
#        Override or augment with your own verification.
#        Typically it's enough to confirm that the output differs from the input
#        '''
#
#        # throw an exception if for some reason we didn't fuzz the input
#        # some fuzzers don't materially alter the file every time, e.g., swap
#        if self.input == self.fuzzed:
#            raise FuzzerInputMatchesOutputError('Fuzz failed: input matches output')

    def _prefuzz(self):
        '''
        Override this method if you want to do some processing before you call
        _fuzz
        '''
        pass

    def _postfuzz(self):
        '''
        Override this method if you want to do some post-processing after
        calling _fuzz
        '''
        pass

    def _fuzz(self):
        '''
        Override this method to implement your fuzzer. The seed file contents
        are in self.input. Put the output into self.fuzzed.
        '''
        # disable fuzzed_changes_input since we're copying in -> out
        self.fuzzed_changes_input = False
        self.fuzzed = self.input

    def _validate(self):
        '''
        Placeholder for subclass methods.
        Raise exceptions if the fuzzer doesn't have what it needs to run.
        '''
        pass

    def _parse_options(self):
        '''
        Placeholder for subclass methods
        '''
        pass


class MinimizableFuzzer(Fuzzer):
    '''
    Convenience class to be used as parent of all minimizable fuzzers (i.e.,
    those change more than one byte but do not alter the length of the file)
    '''
    is_minimizable = True

    def _prefuzz(self):
        if self.options.get('fuzz_zip_container') or not self.sf.is_zip:
            return

        # If the seed is zip-based, fuzz the contents rather than the container
        inmemseed = StringIO.StringIO(self.input)
        try:
            tempzip = zipfile.ZipFile(inmemseed, 'r')
        except:
            logger.warning('Bad zip file. Aborting.')
            self.sf.is_zip = False
            inmemseed.close()
            return

        '''
        get info on all the archived files and concatentate their contents
        into self.input
        '''
        self.input = bytearray()
        logger.debug('Reading files from zip...')
        for i in tempzip.namelist():
            try:
                data = tempzip.read(i)
            except:
                # BadZipfile or encrypted
                logger.warning('Bad zip file. Aborting.')
                self.sf.is_zip = False
                tempzip.close()
                inmemseed.close()
                return

            # save split indices and compression type for archival
            # reconstruction

            # save compress type
            self.saved_arcinfo[i] = (len(self.input), len(data),
                                    tempzip.getinfo(i).compress_type)
            self.input += data
        tempzip.close()
        inmemseed.close()

    def _postfuzz(self):
        if self.options.get('fuzz_zip_container') or not self.sf.is_zip:
            return

        '''rebuild the zip file and put it in self.fuzzed
        Note: We assume that the fuzzer has not changes the lengths
        of the archived files, otherwise we won't be able to properly
        split self.fuzzed
        '''

        logger.debug('Creating in-memory zip with mutated contents.')
        inmemzip = StringIO.StringIO()
        tempzip = zipfile.ZipFile(inmemzip, 'w')

        '''
        reconstruct archived files, using the same compression scheme as the
        source
        '''
        for name, info in self.saved_arcinfo.iteritems():
            # write out fuzzed file
            if info[2] == 0 or info[2] == 8:
                # Python zipfile only supports compression types 0 and 8
                compressiontype = info[2]
            else:
                logger.warning('Compression type %s is not supported. Overriding', info[2])
                compressiontype = 8
            tempzip.writestr(name, str(self.fuzzed[info[0]:info[0] + info[1]]),
                             compress_type=compressiontype)
        tempzip.close()

        # get the byte string version of the archive and put in self.fuzzed
        self.fuzzed = inmemzip.getvalue()
        inmemzip.close()

#     def bitwise_hd(self):
#         '''
#         Convenience function that returns the bitwise hamming distance
#         between input and fuzzed
#         '''
#         fuzzed = [chr(x) for x in self.fuzzed]
#         return bitwise_hd(self.input, fuzzed)
#
#     def bytewise_hd(self):
#         '''
#         Convenience function that returns the bytewise hamming distance
#         between input and fuzzed
#         '''
#         fuzzed = [chr(x) for x in self.fuzzed]
#         return bytewise_hd(self.input, fuzzed)
#
#     def fuzzed_bit_ratio(self):
#         return  self.bitwise_hd() / float(len(self.input) * 8)
#
#     def fuzzed_byte_ratio(self):
#         return  self.bytewise_hd() / float(len(self.input))
