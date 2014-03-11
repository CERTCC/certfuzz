'''
Created on Jan 10, 2014

@author: adh
'''
import logging
import sys
import os
from threading import Timer
import platform

from certfuzz.campaign.campaign import Campaign

from certfuzz.runners.killableprocess import Popen

logger = logging.getLogger(__name__)


class WindowsCampaign(Campaign):
    '''
    Extends Campaign to add windows-specific features like ButtonClicker
    '''
    def __enter__(self):
        if sys.platform == 'win32':
            winver = sys.getwindowsversion().major
            machine = platform.machine()
            hook_incompat = (winver > 5) or (machine == 'AMD64')
            if hook_incompat and self.runner_module_name == 'certfuzz.runners.winrun':
                logger.debug('winrun is not compatible with Windows %s %s. Overriding.', winver, machine)
                self.runner_module_name = None
        self = Campaign.__enter__(self)
        self._start_buttonclicker()
        self._cache_app()
        return self

    def __exit__(self, etype, value, mytraceback):
        self._stop_buttonclicker()
        return Campaign.__exit__(self, etype, value, mytraceback)

    def _cache_app(self):
        logger.debug('Caching application %s and determining if we need to watch the CPU...', self.prog)
        targetdir = os.path.dirname(self.prog)
        # Use overriden Popen that uses a job object to make sure that
        # child processes are killed
        p = Popen(self.prog, cwd=targetdir)
        runtimeout = self.config['runner']['runtimeout']
        logger.debug('...Timer: %f', runtimeout)
        t = Timer(runtimeout, self.kill, args=[p])
        logger.debug('...timer start')
        t.start()
        p.wait()
        logger.debug('...timer stop')
        t.cancel()
        if not self.gui_app:
            logger.debug('This seems to be a CLI application.')
        try:
            runner_watchcpu = str(self.config['runner']['watchcpu']).lower()
            debugger_watchcpu = str(self.config['debugger']['watchcpu']).lower()
        except KeyError:
            self.config['runner']['watchcpu'] = 'auto'
            self.config['debugger']['watchcpu'] = 'auto'
            runner_watchcpu = 'auto'
            debugger_watchcpu = 'auto'
        if runner_watchcpu == 'auto':
            logger.debug('Disabling runner CPU monitoring for dynamic timeout')
            self.config['runner']['watchcpu'] = False
        if debugger_watchcpu == 'auto':
            logger.debug('Disabling debugger CPU monitoring for dynamic timeout')
            self.config['debugger']['watchcpu'] = False

    def kill(self, p):
        # The app didn't complete within the timeout.  Assume it's a GUI app
        logger.debug('This seems to be a GUI application.')
        self.gui_app = True
        try:
            runner_watchcpu = str(self.config['runner']['watchcpu']).lower()
            debugger_watchcpu = str(self.config['debugger']['watchcpu']).lower()
        except KeyError:
            self.config['runner']['watchcpu'] = 'auto'
            self.config['debugger']['watchcpu'] = 'auto'
            runner_watchcpu = 'auto'
            debugger_watchcpu = 'auto'
        if runner_watchcpu == 'auto':
            logger.debug('Enabling runner CPU monitoring for dynamic timeout')
            self.config['runner']['watchcpu'] = True
            logger.debug('kill runner watchcpu: %s', self.config['runner']['watchcpu'])
        if debugger_watchcpu == 'auto':
            logger.debug('Enabling debugger CPU monitoring for dynamic timeout')
            self.config['debugger']['watchcpu'] = True
            logger.debug('kill debugger watchcpu: %s', self.config['debugger']['watchcpu'])
        logger.debug('kill %s', p)
        p.kill()

    def _start_buttonclicker(self):
        if self.use_buttonclicker:
            rootpath = os.path.dirname(sys.argv[0])
            buttonclicker = os.path.join(rootpath, 'buttonclicker', 'buttonclicker.exe')
            os.startfile(buttonclicker)  # @UndefinedVariable

    def _stop_buttonclicker(self):
        if self.use_buttonclicker:
            os.system('taskkill /im buttonclicker.exe')
