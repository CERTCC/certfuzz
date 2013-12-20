# '''
# Created on Jan 17, 2013
#
# @organization: cert.org
# '''
# from pkg_resources import resource_string
# import yaml
# import os
#
# _yaml = resource_string(__name__, 'config.yaml')
# _defaults = yaml.safe_load(_yaml)
# HANDLE_FILE_TIMEOUT = 300
# TOMBSTONE_TIMEOUT = 5
# DBCFG = _defaults['db']
#
# SF_CACHE_DIR = os.path.abspath(os.path.expanduser(_defaults['directories']['seedfile_cache']))
