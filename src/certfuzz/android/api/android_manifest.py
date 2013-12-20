'''
Created on Mar 1, 2013

@organization: cert.org
'''
import logging
import re

logger = logging.getLogger(__name__)

regex = {
         'mimetype': re.compile('A: android:mimeType[^=]*="([^"]+)"'),
         'package': re.compile('A: package[^=]*="([^"]+)"'),
         'version': re.compile('A: android:versionName[^=]*="([^"]+)"')
         }
class AndroidManifest(object):
    def __init__(self, text=None):
        self.lines = text.splitlines()
        self.parsed = {}
        self.parsed['mimetypes'] = set()

        self.callbacks = [self._get_mimetypes,
                               self._log_line,
                               self._get_package,
                               self._get_version,
                               ]
        self._parse()

    @property
    def version_info(self):
        return '{} {}'.format(self.parsed['package'], self.parsed['version'])

    @property
    def mimetypes(self):
        return self.parsed['mimetypes']

    def _get_mimetypes(self, line):
        m = re.match(regex['mimetype'], line)
        if m:
            self.parsed['mimetypes'].add(m.group(1))

    def _get_package(self, line):
        m = re.match(regex['package'], line)
        if m:
            self.parsed['package'] = m.group(1)
            self.callbacks.remove(self._get_package)

    def _get_version(self, line):
        m = re.match(regex['version'], line)
        if m:
            self.parsed['version'] = m.group(1)
            self.callbacks.remove(self._get_version)


    def _log_line(self, line):
        logger.debug(line)

    def _parse(self):

        for line in self.lines:
            l = line.strip()
            for callback in self.callbacks:
                callback(l)
