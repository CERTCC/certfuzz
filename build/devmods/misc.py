'''
Created on Dec 9, 2013

@author: adh
'''
import logging
import os
from distutils import dir_util
import shutil

logger = logging.getLogger(__name__)


def onerror(func, path, exc_info):
    """
    Error handler for ``shutil.rmtree``.

    If the error is due to an access error (read only file)
    it attempts to add write permission and then retries.

    If the error is for another reason it re-raises the error.

    Usage : ``shutil.rmtree(path, onerror=onerror)``
    """
    import stat
    if not os.access(path, os.W_OK):
        # Is the error an access error ?
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        raise


def copydir(src, dst):
    logger.info('Copy dir  %s -> %s', src, dst)
    dir_util.copy_tree(src, dst)


def copyfile(src, dst):
    logger.info('Copy file %s -> %s', src, dst)
    shutil.copy(src, dst)


def stripmarkdown(markdown):
    replacements = {'&copy;': '(C)', '&reg;': '(R)'}
    for k, v in replacements.iteritems():
        markdown = markdown.replace(k, v)
    return markdown


def mdtotextfile(markdownfile, plaintextfile):
    logger.info('Converting markdown file %s to plain text %s' %
                (markdownfile, plaintextfile))
    f = open(markdownfile, 'r')
    markdown = f.read()
    f.close
    plaintext = stripmarkdown(markdown)
    f = open(plaintextfile, 'w')
    f.write(plaintext)
    f.close
