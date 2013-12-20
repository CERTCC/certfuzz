'''
Created on Oct 24, 2012

@organization: cert.org
'''
class Mock(object):
    pass

class MockRange(Mock):
    def __init__(self):
        self.min = 0.01
        self.max = 0.10

class MockRangefinder(Mock):
    def next_item(self):
        return MockRange()

class MockSeedfile(Mock):
    def __init__(self, sz=1000):
        self.basename = 'basename'
        self.root = 'root'
        self.ext = '.ext'
        self.tries = 0
        self.value = 'A' * sz
        self.len = len(self.value)
        self.rangefinder = MockRangefinder()

    def read(self):
        return self.value
