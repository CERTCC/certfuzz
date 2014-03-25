'''
Created on Jul 10, 2012

@organization: cert.org
'''
from setuptools import setup, find_packages
import platform


def _bff_for_platform():
    parts = ['certfuzz', 'bff']
    _platform = platform.system()
    if _platform == 'Windows':
        parts.append('windows')
    else:
        # actually covers linux and osx
        parts.append('linux')

    module = '.'.join(parts)
    return module

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
             'windows': ['clean_foe',
                         'copycrashers',
                         'drillresults',
                         'minimize',
                         'mtsp_enum',
                         'quickstats',
                         'repro',
                         'zipdiff',
                         ],
             }


def _platform_scripts():
    '''
    Assumes tool foo will have an entry point certfuzz.tools.<platform>.foo:main
    :param _platform:
    '''
    _platform = platform.system().lower()
    script_spec_template = '{} = certfuzz.tools.{}.{}:main'
    scripts = []

    for s in TOOL_NAMES[_platform]:
        # will turn "callsim" into "callsim = certfuzz.tools.linux.callsim"
        scripts.append(script_spec_template.format(s, _platform, s))

    return scripts

def get_entry_points():
    '''
    Returns a dict containing entry points.
    '''
    console_scripts = []
    console_scripts.append('bff = {}:main'.format(_bff_for_platform()))

    console_scripts.extend(_platform_scripts())

    eps = {}
    eps['console_scripts'] = console_scripts
    return eps

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
                        'matplotlib',
                        ],
      scripts=[
#            'scripts/start_bff_android.sh',
#            'scripts/reset_bff_android.sh',
#            'scripts/ubufuzz_first_time_setup.sh',
               ],
      entry_points=get_entry_points(),
      include_package_data=True,
      license='See LICENSE.txt',
      data_files=[
                    ('', ['LICENSE.txt'])
                    ]
      )
