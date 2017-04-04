'''
Created on Feb 22, 2011

@organization: cert.org
'''
# from numpy import dot
# from numpy.linalg import norm
import math


def compare(d1, d2):
    '''
    Turn two dicts into vectors, then calculate their similarity
    @param d1: a dict with numeric values
    @param d2: a dict with numeric values
    '''

    # get the set of all keys for the two dicts
    k1 = set(d1.keys())
    k2 = set(d2.keys())
    keyset = k1.union(k2)

    # build vectors
    v1 = []
    v2 = []

    for k in keyset:
        v1.append(d1.get(k, 0))
        v2.append(d2.get(k, 0))

    return similarity(v1, v2)


def similarity(v1, v2):
    return cos(v1, v2)


def cos(v1, v2):
    assert len(v1) == len(v2), 'Cannot compare vectors of unequal length'
    dotproduct = float(dot(v1, v2))
    norm1 = float(norm(v1))
    norm2 = float(norm(v2))
    sim = dotproduct / (norm1 * norm2)
    sim = float('%.6f' % sim)  # fix for floating point very near 1.0 BFF-234
    assert 0 <= sim <= 1.0, 'Similarity out of range: %f' % sim

    return sim


def dot(v1, v2):
    '''
    Calculate the sum of the products of each term in v1 and v2
    @param v1:
    @param v2:
    '''
    assert len(v1) == len(v2), 'Vectors are different lengths'

    terms = list(zip(v1, v2))
    products = [float(x) * float(y) for (x, y) in terms]
    total = sum(products)
    return total


def norm(v):
    squares = [float(x) * float(x) for x in v]
    total = sum(squares)
    sqrt = math.sqrt(total)
    return sqrt


class Vector(object):
    def __init__(self, v):
        self.vector = v
