Use make_dev.py to copy files in a dev environment to a different dir for use by 
your test VM.

Use make_dist2.py to build a distributable package.

usage: make_dist2.py [-h] [-d] [-v] platform srcpath distpath

positional arguments:
  platform       One of ['windows', 'darwin', 'linux']
  srcpath        path/to/bff/src
  distpath       Directory to build into

optional arguments:
  -h, --help     show this help message and exit
  -d, --debug    enable debug messages
  -v, --verbose  enable debug messages