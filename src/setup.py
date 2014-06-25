'''
Created on Jul 10, 2012

@organization: cert.org
'''
from setuptools import setup, find_packages
import platform


TOOL_NAMES = {'linux': ['bff_stats',
                        'callsim',
                        'create_crasher_script',
                        'debugger_file',
                        'drillresults',
                        'minimize',
                        'minimizer_plot',
                        'mtsp_enum',
                        'repro',
                        ],
             'windows': ['clean_windows',
                         'copycrashers',
                         'drillresults',
                         'minimize',
                         'mtsp_enum',
                         'quickstats',
                         'repro',
                         'zipdiff',
                         ],
             }


def _ep_scripts(target_platform):
    '''
    Assumes tool foo will have an entry point certfuzz.tools.<platform>.foo:main
    :param _platform:
    '''
    script_spec_template = '{} = certfuzz.tools.{}.{}:main'
    scripts = []

    for s in TOOL_NAMES[target_platform]:
        # will turn "callsim" into "callsim = certfuzz.tools.linux.callsim"
        scripts.append(script_spec_template.format(s, target_platform, s))

    return scripts


def _entry_points():
    '''
    Returns a dict containing entry points.
    '''
    bff_template = 'bff = certfuzz.bff.{}:main'

    _platform = platform.system().lower()
    if _platform == 'darwin':
        _platform = 'linux'

    console_scripts = []
    console_scripts.append(bff_template.format(_platform))
    console_scripts.extend(_ep_scripts(_platform))

    eps = {}
    eps['console_scripts'] = console_scripts
    return eps

def _scripts():
    _s = [
#            'scripts/start_bff_android.sh',
#            'scripts/reset_bff_android.sh',
#            'scripts/ubufuzz_first_time_setup.sh',
               ]
    return _s

setup(name="CERT_Basic_Fuzzing_Framework",
      version="3.0a",
      description="CERT Basic Fuzzing Framework 3.0",
      author="CERT",
      author_email="cert@cert.org",
      url="http://www.cert.org",
      maintainer='CERT',
      maintainer_email='cert@cert.org',
      download_url='http://www.cert.org/download/bff/',
      packages=find_packages(where='.'),
      install_requires=[
                        'pyyaml',
#                        'couchdb',
                        'numpy',
#                        'matplotlib',
                        ],
      scripts=_scripts(),
      entry_points=_entry_points(),
      include_package_data=True,
      test_suite='certfuzz.test',
      license='See LICENSE.txt',
      data_files=[
                    ('', ['LICENSE.txt'])
                    ]
      )
