'''
Created on Apr 5, 2012

@organization: cert.org
'''
from certfuzz.fuzzers.copy import CopyFuzzer
from certfuzz.fuzzers.errors import FuzzerExhaustedError


_files_seen = set()


class VerifyFuzzer(CopyFuzzer):
    '''
    Adds a uniquness function to the CopyFuzzer
    '''
    def _fuzz(self):
        # get the hash of the source file
        md5 = self.sf.md5

        if md5 in _files_seen:
            # this is a repeat. Raise a flag
            raise FuzzerExhaustedError

        # otherwise just remember this for next time
        _files_seen.add(md5)
        # and do the normal copy fuzzer thing
        CopyFuzzer._fuzz(self)

_fuzzer_class = VerifyFuzzer
