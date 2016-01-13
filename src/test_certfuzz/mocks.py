'''
Created on Oct 24, 2012

@organization: cert.org
'''
import hashlib
import logging

class Mock(object):
    pass

class MockRange(Mock):
    def __init__(self):
        self.min = 0.01
        self.max = 0.10

    def __str__(self):
        return '{}-{}'.format(self.min, self.max)

class MockRangefinder(Mock):
    def next_item(self):
        return MockRange()

class MockSeedfile(Mock):
    basename = 'basename'
    root = 'root'
    ext = '.ext'
    tries = 0
    rangefinder = MockRangefinder()

    def __init__(self, sz=1000):
        self.value = 'A' * sz
        self.md5 = hashlib.md5(self.value).hexdigest()
        self.len = len(self.value)

    def read(self):
        return self.value

class MockFuzzedFile(Mock):
    path = u'foo'

class MockFuzzer(Mock):
    is_minimizable = False

class MockTestcase(Mock):
    signature = 'ABCDEFGHIJK'
    logger = logging.getLogger('mocktestcaselogger')
    seedfile = MockSeedfile()
    seednum = 123456789
    range = MockRange()
    fuzzedfile = MockFuzzedFile()
    pc = u'dummyPCstring'
