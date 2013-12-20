'''
Created on Dec 13, 2012

@organization: cert.org
'''
import multiprocessing
import logging
from emulator_manager import drone

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

def _drone_pool(num_procs):
    pool = multiprocessing.Pool(processes=num_procs)
    pool.map(drone, range(num_procs))
    pool.terminate()

def _drone_loop(num_procs):
#    lock = multiprocessing.Lock()
    for i in range(num_procs):
        multiprocessing.Process(target=drone, args=(i,)).start()

def hive_queen(num_procs):
    if not num_procs:
        # procs_per_cpu > 1.0 => oversubscribe
        # procs_per_cpu < 1.0 => undersubscribe
        procs_per_cpu = 1.0
        num_procs = int(multiprocessing.cpu_count() * procs_per_cpu)

#    _drone_pool(num_procs)
    _drone_loop(num_procs)

if __name__ == '__main__':
    from argparse import ArgumentParser

    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    hdlr = logging.FileHandler('emu.log')
    logger.addHandler(hdlr)

    parser = ArgumentParser(description='Spawn Android Emulators')
    parser.add_argument('--numprocs', dest='numprocs', type=int)
    args = parser.parse_args()

    logger.info('Parsed args: %s', args)

    hive_queen(num_procs=args.numprocs)
