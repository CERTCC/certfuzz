Use make_dev.py to copy files in a dev environment to a different dir for use by 
your test VM.

Use make_dist2.py to build a distributable package.

floyd:build adh$ python make_dist2.py --help
usage: make_dist2.py [-h] [-d] [-v] platform srcpath distpath

positional arguments:
  platform       One of ['windows', 'osx', 'linux']
  srcpath        path/to/bff/src
  distpath       Directory to build into

optional arguments:
  -h, --help     show this help message and exit
  -d, --debug    enable debug messages
  -v, --verbose  enable debug messages


**NOTE**
As of 2014-02-11 This only works for "linux". Windows and OSX build capability will
follow soon.


make_dist.py is broken. Or rather, it depends on the code being in subversion,
which is no longer true.

