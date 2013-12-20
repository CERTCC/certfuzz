'''
Created on Jan 14, 2013

@organization: cert.org
'''
import os
from functools import partial
from .errors import Android_API_Error


_defaults = {'sdk_home': os.path.abspath(os.path.expanduser('~/android-sdk')),
             'avd_home': os.path.abspath(os.path.expanduser('~/.android/avd'))
             }

# set env vars to check (overrides config.yaml)
_env_key = lambda x: 'ANDROID_%s' % x.upper()
for key in ['sdk_home', 'avd_home']:
    _defaults[key] = os.getenv(_env_key(key), _defaults[key])

# convert to expanded paths
_defaults['sdk_home'] = os.path.expanduser(_defaults['sdk_home'])
_defaults['avd_home'] = os.path.expanduser(_defaults['avd_home'])

if not os.path.isdir(_defaults['sdk_home']):
    raise Android_API_Error('No Android SDK found at %s, '
                            'try setting %s environment var'
                            % (_defaults['sdk_home'], _env_key('sdk_home')))

_sdk_relpath = partial(os.path.join, _defaults['sdk_home'])

# usage: sdk_tool('android'), sdk_platform_tool('adb') etc.
sdk_tool = partial(_sdk_relpath, 'tools')
sdk_platform_tool = partial(_sdk_relpath, 'platform-tools')

if not os.path.isdir(sdk_tool()):
    raise Android_API_Error('SDK tool dir not found at %s. '
                            'Is %s really an Android SDK dir?' % (sdk_tool(),
                                                                  _defaults['sdk_home']))
if not os.path.isdir(sdk_platform_tool()):
    raise Android_API_Error('SDK platform tool dir not found at %s. '
                            'Is %s really an Android SDK dir?' % (sdk_platform_tool(),
                                                                  _defaults['sdk_home']))

if not os.path.isdir(_defaults['avd_home']):
    raise Android_API_Error('No Android AVD dir found at %s,'
                            'try setting %s environment var'
                            % (_defaults['avd_home'], _env_key('avd_home')))
AVD_HOME = _defaults['avd_home']

# string formatters
avddir_basename = '{}.avd'.format
inifile_basename = '{}.ini'.format
avd_home = lambda x: os.path.join(_defaults['avd_home'], x)

# convenience functions for fullpath versions
avddir = lambda x: avd_home(avddir_basename(x))
inifile = lambda x: avd_home(inifile_basename(x))

# TIMERS = {}
# for k, v in _defaults['timers'].iteritems():
#     TIMERS[k.upper()] = v
