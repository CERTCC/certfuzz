'''
Created on Jul 10, 2013

@organization: cert.org
'''

import os
import collections
import zipfile
from optparse import OptionParser

saved_arcinfo = collections.OrderedDict()


def readzip(filepath):
    global savedarcinfo
    # If the seed is zip-based, fuzz the contents rather than the container
    tempzip = zipfile.ZipFile(filepath, 'r')

    '''
    get info on all the archived files and concatentate their contents
    into self.input
    '''
    unzippedbytes = ''
    for i in tempzip.namelist():
        data = tempzip.read(i)

        # save split indices and compression type for archival reconstruction

        saved_arcinfo[i] = (len(unzippedbytes), len(data))
        unzippedbytes += data
    tempzip.close()
    return unzippedbytes


def main():
    global saved_arcinfo
    usage = 'usage: %prog zip1 zip2'
    parser = OptionParser(usage=usage)
    (options, args) = parser.parse_args()

    if len(args) != 2:
        parser.error('Incorrect number of arguments')
        return

    changedbytes = []
    changedfiles = []

    zip1 = args[0]
    zip2 = args[1]
    zip1bytes = readzip(zip1)
    zip2bytes = readzip(zip2)
    zip1len = len(zip1bytes)

    if zip1len != len(zip2bytes):
        print('Zip contents are not the same size. Aborting.')

    for i in range(0, zip1len):
        if zip1bytes[i] != zip2bytes[i]:
#            print 'Zip contents differ at offset %s' % i
            changedbytes.append(i)

    for changedbyte in changedbytes:
        for name, info in saved_arcinfo.items():
            startaddr = info[0]
            endaddr = info[0] + info[1]
            if startaddr <= changedbyte <= endaddr and name not in changedfiles:
                print('%s modified' % name)
                changedfiles.append(name)
            #print '%s: %s-%s' %(name, info[0], info[0]+info[1])


if __name__ == '__main__':
    main()
