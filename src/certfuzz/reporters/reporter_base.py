'''
Created on Jan 12, 2016

@author: adh
'''
import abc

class ReporterBase(object, metaclass=abc.ABCMeta):
    '''
    A BFF Reporter class
    '''

    def __init__(self, testcase):
        '''
        Constructor
        '''
        self.testcase = testcase

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        pass

    @abc.abstractmethod
    def go(self):
        pass
