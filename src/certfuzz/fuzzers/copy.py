from . import Fuzzer

class CopyFuzzer(Fuzzer):
    '''
    This "fuzzer" copies input_file_path to output_file_path. Useful for
    testing and "refining" a set of crashing test cases through a debugger.
    '''
    pass

_fuzzer_class = CopyFuzzer
