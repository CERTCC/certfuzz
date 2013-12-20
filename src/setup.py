'''
Created on Jul 10, 2012

@organization: cert.org
'''
from setuptools import setup, find_packages

setup(name="CERT_Basic_Fuzzing_Framework",
      version="1.0-android",
      description="A fuzzing framework for Android, based on BFF 2.7",
      author="CERT",
      author_email="cert@cert.org",
      url="http://www.cert.org",
      maintainer='CERT',
      maintainer_email='cert@cert.org',
      download_url='http://www.cert.org/download/bff/',
      packages=find_packages(where='.'),
      install_requires=[
                        'pyyaml',
                        'couchdb',
                        'numpy',
                        ],
      scripts=['scripts/start_bff_android.sh',
               'scripts/reset_bff_android.sh',
               'scripts/ubufuzz_first_time_setup.sh',
               ],
      entry_points={'console_scripts': [
            'bff_avd_mgr = certfuzz.android.avd_mgr.main:main',
            'bff_android = certfuzz.android.controller.bff_android:main',
            'bff_avd_cloner = certfuzz.android.celery.avd_mgr.cloner:main',
            'bff_apk_dumper = certfuzz.android.tools.apk_dumper:main',
            'config_init = certfuzz.android.tools.config_tools:main'
            ]},
      include_package_data=True,
      )
