'''
Created on Dec 9, 2013

@author: adh
'''
import os
import logging
import shutil
import subprocess

from .errors import BuildError
from .svn import svn_export, svn_rev
from .misc import mkdir_p
import urlparse

logger = logging.getLogger(__name__)


def _add_trailing_slash(url):
    if url.endswith('/'):
        return url
    return url + '/'


class Build(object):
    '''
    classdocs
    '''
    PROJECT = 'BFF'

    PLATFORM = None
    LICENSE_FILE = 'COPYING'
    PWD = os.path.abspath(os.path.dirname(__file__))
    BUILD_BASE = PWD
    DIST_BASE = os.path.abspath(os.path.join(PWD, '../../dist_builds'))

    def __init__(self, buildtype, args, url=None, platform=None):
        '''
        Constructor
        '''
        self.buildtype = buildtype
        self.args = args
        if platform:
            self.platform = platform
        else:
            self.platform = self.PLATFORM

        _url = _add_trailing_slash(url)

        # urlparse.urljoin doesn't work right with svn:// URIs. But it should.
        # https://mail.python.org/pipermail/python-bugs-list/2011-August/145058.html
        self.trunk = '%s/trunk' % _url
        self.branches = '%s/branches' % _url
        self.tags = '%s/tags' % _url

        self.build_dir = None
        self.export_path = None
        self.svn_rev = None
        self.branch = None
        self.svn_url = None
        self.zipfile_template = None
        self.tag = None

        # set the default export function
        # note: buildtype=trunk will override this in process_args
        self.export = self._export

        self.export_base = '%s-%s-export' % (self.PROJECT, self.platform)
        self.zipfile = None
        self.in_runtime_context = False

    def __enter__(self):
        '''
        Set up the runtime context for with... syntax
        '''
        self.process_args()

        if not os.path.exists(self.DIST_BASE):
            mkdir_p(self.DIST_BASE)

        import tempfile
        pfx = '%s-%s-' % (self.PROJECT, self.platform)
        self.build_dir = tempfile.mkdtemp(prefix=pfx, dir=self.DIST_BASE)
        self.export_path = os.path.join(self.build_dir, self.export_base)
        self.in_runtime_context = True
        logger.info('Starting build')
        return self

    def __exit__(self, etype, value, traceback):
        '''
        Teardown the runtime context
        :param etype:
        :param value:
        :param traceback:
        '''
        self.in_runtime_context = False

        # only clean up if we're exiting normally
        if not etype:
            logger.info('Build complete, cleaning up')
            shutil.rmtree(self.build_dir)
        logger.info('Exiting build')

    def process_args(self):
        '''
        Process the other arguments passed to the build object
        '''
        if self.buildtype == 'tag':
            if not len(self.args):
                raise BuildError('Build type %s requires a tag' % self.buildtype)
            self.tag = self.args.pop(0)
            self.svn_url = "%s/%s" % (self.tags, self.tag)
            self.zipfile = '%s-%s.zip' % (self.PROJECT, self.tag)
        elif self.buildtype == 'branch':
            if not len(self.args):
                raise BuildError('Build type %s requires a tag' % self.buildtype)
            self.branch = self.args.pop(0)
            self.svn_url = "%s/%s" % (self.branches, self.branch)
            self.zipfile_template = '%s-%s-r$SVN_REV.zip' % (self.PROJECT, self.branch)
        elif self.buildtype == 'trunk':
#            # TODO remove the self.export line when 2.6 is merged back to trunk
#            self.export = self._export_pre_2_6
            self.svn_url = self.trunk
            self.zipfile_template = '%s-trunk-r$SVN_REV.zip' % (self.PROJECT)
        else:
            raise BuildError('Unknown buildtype: %s' % self.buildtype)

    def build(self):
        '''
        Perform a build. Must be invoked using with Build(foo)... syntax
        '''
        assert self.in_runtime_context, 'Build() must be invoked using with... syntax'
        logger.info('Exporting')
        self.export()
        logger.info('Pruning')
        self.prune()
        logger.info('Refining')
        self.refine()
        logger.info('Prepending license')
        self.prepend_license()
        logger.info('Packaging')
        self.package()

    def _export_pre_2_6(self):
        '''
        Exports pre-2.6 code from the repository. When complete, the code will be
        in the directory specified by self.export_path
        '''
        svn_base = "%s/src" % self.svn_url
        src = svn_base
        dst = self.export_path
        svn_export(src, dst)
        self.svn_rev = svn_rev(svn_base)

    def _export(self):
        '''
        Exports the code from the repository. When complete, the code will be
        in the directory specified by self.export_path
        '''
        svn_base = "%s/src" % self.svn_url
        for d in [self.platform, 'certfuzz', 'seedfiles']:
            src = "%s/%s" % (svn_base, d)
            if d == self.platform:
                dst = self.export_path
            else:
                dst = os.path.join(self.export_path, d)
            svn_export(src, dst)
        self.svn_rev = svn_rev(svn_base)

    def refine(self):
        '''
        Post-export refinement of the code prior to packaging.
        '''
        result_dir = os.path.join(self.export_path, 'results')
        mkdir_p(result_dir)

    def prepend_license(self):
        '''
        Adds the license text to the code prior to packaging
        '''
        # TODO refactor this to call prepend_license in a pythonic way
        # rather than shelling it out
        args = ['python', '%s/prepend_license.py' % self.PWD,
                '--add',
                '--dir', self.export_path,
                '--license', os.path.join(self.export_path, self.LICENSE_FILE),
                '--overwrite',
                '--verbose',
                ]
        subprocess.call(args)

    def prune(self):
        '''
        Prunes unneeded code from the export prior to packaging
        '''
        for dirname, _dirnames, _filenames in os.walk(self.export_path):
            if os.path.basename(dirname) == 'obsolete':
                logger.info("Removing %s" % dirname)
                shutil.rmtree(dirname)

    def package(self):
        '''
        Packages the code for distribution
        '''
        raise NotImplementedError
