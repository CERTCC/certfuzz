'''
Created on Jan 17, 2013

@organization: cert.org
'''
import logging
import os
from ..campaign.campaign_android import AndroidCampaign
from ..fuzztools import filetools
from ..campaign.errors import AndroidCampaignError
from ..android.api.log_helper import log_formatter


logger = logging.getLogger()


def setup_logging(log_level=logging.WARNING,
                  log_dir=None,
                  log_basename='bff.log'):

    formatter = log_formatter()

    log_handlers = []

    # console logging
    log_handlers.append(logging.StreamHandler())

    # file logging
    if log_dir is not None:
        filetools.make_directories(log_dir)
        logfile = os.path.join(log_dir, log_basename)
        log_handlers.append(logging.FileHandler(logfile, mode='w'))

    for hdlr in log_handlers:
        hdlr.setFormatter(formatter)
        logger.addHandler(hdlr)

    logger.setLevel(log_level)


def main():
    log_level = logging.WARNING

    default_cfg = 'config/android_config.yaml'
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('repeat_count', type=int, default=None)
    parser.add_argument('--intent_yaml', type=str, default=None)
    parser.add_argument('--config', type=str, default=default_cfg)
    parser.add_argument('--verbose', action='store_true', default=False)
    parser.add_argument('--debug', action='store_true', default=False)
    args = parser.parse_args()

    if args.debug:
        log_level = logging.DEBUG
    elif args.verbose:
        log_level = logging.INFO

    setup_logging(log_level, log_dir='log')

    if args.config != default_cfg:
        if not os.path.exists(args.config):
            logger.error('Could not find config %s' % args.config)
            return

    if os.path.exists(args.config):
        custom_cfg = args.config
        logger.info('Using config file: %s' % custom_cfg)
    else:
        logger.error('Could not find %s' % args.config)
        logger.warning('Using default config at %s' % default_cfg)
        custom_cfg = default_cfg

    try:
        with AndroidCampaign(config_file=custom_cfg,
                             intent_yaml=args.intent_yaml,
                             repeat_count=args.repeat_count) as c:
            c.go()
    except AndroidCampaignError as e:
        logger.warning('Campaign terminated due to: %s', e)


if __name__ == '__main__':
    main()
