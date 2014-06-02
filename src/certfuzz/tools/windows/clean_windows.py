'''
Created on Feb 28, 2012

@author: adh
'''

import os
import time
import tempfile
import pprint

defaults = {'config': 'configs/bff.yaml',
            'remove_results': False,
            'pretend': False,
            'retry': 3,
            'debug': False,
            'nuke': False,
          }

SLEEPTIMER = 0.5
BACKOFF_FACTOR = 2


def main():
    import optparse
    try:
        from certfuzz.fuzztools.filetools import delete_contents_of
        from certfuzz.campaign.config import Config
    except ImportError:
        # if we got here, we probably don't have .. in our PYTHONPATH
        import sys
        mydir = os.path.dirname(os.path.abspath(__file__))
        parentdir = os.path.abspath(os.path.join(mydir, '..'))
        sys.path.append(parentdir)
        from certfuzz.fuzztools.filetools import delete_contents_of
        from certfuzz.campaign.config import Config
        if not os.path.exists(defaults['config']):
            defaults['config'] = '../configs/bff.yaml'

    parser = optparse.OptionParser()
    parser.add_option('-c', '--config', dest='configfile', default=defaults['config'], metavar='FILE')
    parser.add_option('-p', '--pretend', dest='pretend', action='store_true', default=defaults['pretend'], help='Do not actually remove files')
    parser.add_option('-r', '--retry', dest='retries', default=defaults['retry'], type='int', metavar='INT')
    parser.add_option('', '--remove-results', dest='remove_results', action='store_true', default=defaults['remove_results'], help='Removes results dir contents')
    parser.add_option('', '--all', dest='nuke', action='store_true', default=defaults['nuke'], help='Equivalent to --remove-results')
    parser.add_option('', '--debug', dest='debug', action='store_true', default=defaults['debug'])
    options, _args = parser.parse_args()

    cfgobj = Config(options.configfile)
    c = cfgobj.config

    if options.debug:
        pprint.pprint(c)

    dirs = set()

    if options.nuke:
        options.remove_results = True

    dirs.add(os.path.abspath(c['directories']['working_dir']))
    dirs.add(os.path.join(os.path.abspath(c['directories']['results_dir']), c['campaign']['id'], 'seedfiles'))
    if options.remove_results:
        dirs.add(os.path.join(os.path.abspath(c['directories']['results_dir']), c['campaign']['id'],))

    # add temp dir(s) if available
    if tempfile.gettempdir().lower() != os.getcwd().lower():
        # Only add tempdir if it's valid.  Otherwise you get cwd
        dirs.add(tempfile.gettempdir())
    try:
        dirs.add(os.environ['TMP'])
    except KeyError:
        pass

    try:
        dirs.add(os.environ['TEMP'])
    except KeyError:
        pass

    if not options.pretend:
        tries = 0
        done = False
        skipped = []
        while not done:
            skipped = delete_contents_of(dirs, print_via_log=False)
            # if we got here, no exceptions were thrown
            # so we're done
            if skipped:
                if tries < options.retries:
                    # typically exceptions happen because the OS hasn't
                    # caught up with file lock status, so give it a chance
                    # to do so before the next iteration
                    nap_length = SLEEPTIMER * pow(BACKOFF_FACTOR, tries)
                    tries += 1
                    print '%d files skipped, waiting %0.1fs to retry (%d of %d)' % (len(skipped), nap_length, tries, options.retries)
                    time.sleep(nap_length)
                else:
                    print 'Maximum retries (%d) exceeded.' % options.retries
                    done = True
            else:
                done = True

        for (skipped_item, reason) in skipped:
            print "Skipped file %s: %s" % (skipped_item, reason)

    else:
        parser.print_help()
        print
        print 'Would have deleted the contents of:'
        for d in dirs:
            print '... %s' % d

if __name__ == '__main__':
    main()
