'''
Created on Oct 5, 2010

@organization: cert.org@cert.org

Provides the ability to calculate byte-wise or bit-wise Hamming Distance
between objects. P
'''
import itertools
import os

def vector_compare(v1, v2):
    '''
    Given two sparse vectors (lists of indices whose value is 1), return the distance between them
    '''
    vdict = {}

    for v in v1, v2:
        for idx in v:
            if vdict.get(idx):
                vdict[idx] += 1
            else:
                vdict[idx] = 1

    distance = 0
    for val in vdict.values():
        if val == 1:
            distance += 1

    return distance

def bytemap(s1, s2):
    '''
    Given two strings of equal length, return the indices of bytes that differ.
    '''
    assert len(s1) == len(s2)
    delta = []
    for idx, (c1, c2) in enumerate(itertools.izip(s1, s2)):
        if c1 != c2:
            delta.append(idx)
    return delta

def bytewise_hd(s1, s2):
    '''
    Compute the byte-wise Hamming Distance between two strings. Returns
    the distance as an int.
    '''
    assert len(s1) == len(s2)
    return sum(ch1 != ch2 for ch1, ch2 in itertools.izip(s1, s2))

def bytewise_hamming_distance(file1, file2):
    '''
    Given the names of two files, compute the byte-wise Hamming Distance
    between them. Returns the distance as an int. Throws an AssertionError
    unless file1 and file2 are the same size.
    '''
    return _file_compare(bytewise_hd, file1, file2)

def _file_compare(distance_function, file1, file2):
    assert os.path.getsize(file1) == os.path.getsize(file2)

    distance = 0
    with open(file1, 'rb') as f1:
        with open(file2, 'rb') as f2:
            # find the hamming distance for each byte
            distance = distance_function(f1.read(), f2.read())
    return distance

def bitwise_hd(x, y):
    '''
    Given two strings x and y, find the bitwise hamming distance
    between them. Returns the distance as an int. Throws an AssertionError
    unless x and y are the same size.
    '''
    assert len(x) == len(y)

    hd = 0
    for (a, b) in itertools.izip(x, y):
        a = ord(a)
        b = ord(b)

        v = a ^ b
        while v:
            v = v & (v - 1)
            hd += 1
    return hd

def bitwise_hamming_distance(file1, file2):
    '''
    Given the names of two files, compute the bit-wise Hamming Distance
    between them. Returns the distance as an int. Throws an AssertionError
    unless file1 and file2 are the same size.
    '''
    return _file_compare(bitwise_hd, file1, file2)
