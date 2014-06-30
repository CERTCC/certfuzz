'''
This script looks for interesting crashes and rate them by potential exploitability
'''

import os
import struct
import binascii
import re
from optparse import OptionParser

from certfuzz.tools.common.drillresults import readfile, carve, carve2, \
    score_reports

regex = {
        'gdb_report': re.compile(r'.+.gdb$'),
        'current_instr': re.compile(r'^=>\s(0x[0-9a-fA-F]+)(.+)?:\s+(\S.+)'),
        'frame0': re.compile(r'^#0\s+(0x[0-9a-fA-F]+)\s.+'),
        'regs1': re.compile(r'^eax=.+'),
        'regs2': re.compile(r'^eip=.+'),
        'bt_addr': re.compile(r'(0x[0-9a-fA-F]+)\s+.+$'),
        '64bit_debugger': re.compile(r'^Microsoft.*AMD64$'),
        'syswow64': re.compile(r'ModLoad:.*syswow64.*', re.IGNORECASE),
        'mapped_frame': re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+0(x0)?\s+(/.+)'),
        'vdso': re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+0(x0)?\s+\[vdso\]'),
        'mapped_address': re.compile(r'^ModLoad: ([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(.+)'),
        'mapped_address64': re.compile(r'^ModLoad: ([0-9a-fA-F]+`[0-9a-fA-F]+)\s+([0-9a-fA-F]+`[0-9a-fA-F]+)\s+(.+)'),
        'syswow64': re.compile(r'ModLoad:.*syswow64.*', re.IGNORECASE),
        'dbg_prompt': re.compile(r'^[0-9]:[0-9][0-9][0-9]> (.*)'),
        }

registers = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi',
             'edi', 'eip')

registers64 = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi',
               'rdi', 'rip', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13',
               'r14', 'r15')

# These !exploitable short descriptions indicate a very interesting crash
really_exploitable = [
                      'SegFaultOnPc',
                      'BranchAv',
                      'StackCodeExection',
                      'BadInstruction',
                      'ReturnAv',
                      ]
reg_set = set(registers)
reg64_set = set(registers64)
re_set = set(really_exploitable)

results = {}
scoredcrashes = {}
#regdict = {}
gdblist = []
ignorejit = False
_64bit_debugger = False


def check_64bit(reporttext):
    '''
    Check if the debugger and target app are 64-bit
    '''
    global _64bit_debugger

    if _64bit_debugger:
        return

    for line in reporttext.splitlines():
        m = re.match(regex['bt_addr'], line)
        if m:
            start_addr = m.group(1)
            #print '%s length: %s'% (start_addr, len(start_addr))
            if len(start_addr) > 10:
                _64bit_debugger = True
                #print 'Target process is 64-bit'
                break


def pc_in_mapped_address(reporttext, instraddr):
    '''
    Check if the instruction pointer is in a loaded module
    '''
    if not instraddr:
        # The gdb file doesn't have anything in it that'll tell us
        # where the PC is.
        return ''
#    print 'checking if %s is mapped...' % instraddr
    mapped_module = 'unloaded'

    instraddr = int(instraddr, 16)
#    print 'instraddr: %d' % instraddr
    for line in reporttext.splitlines():
        #print 'checking: %s for %s' % (line,regex['mapped_frame'])
        n = re.search(regex['mapped_frame'], line)
        if n:
#            print '*** found mapped address regex!'
            # Strip out backticks present on 64-bit systems
            begin_address = int(n.group(1).replace('`', ''), 16)
            end_address = int(n.group(2).replace('`', ''), 16)
            if begin_address < instraddr < end_address:
                mapped_module = n.group(4)
                #print 'mapped_module: %s' % mapped_module
        else:
            # [vdso] still counts as a mapped module
            n = re.search(regex['vdso'], line)
            if n:
                begin_address = int(n.group(1).replace('`', ''), 16)
                end_address = int(n.group(2).replace('`', ''), 16)
                if begin_address < instraddr < end_address:
                    mapped_module = '[vdso]'

    return mapped_module


def fixefabug(reporttext, instraddr, faultaddr):
    '''
    !exploitable often reports an incorrect EFA for 64-bit targets.
    If we're dealing with a 64-bit target, we can second-guess the reported EFA
    '''
    instructionline = getinstr(reporttext, instraddr)
    if not instructionline:
        return faultaddr
    ds = carve(instructionline, "ds:", "=")
    if ds:
        faultaddr = ds.replace('`', '')
    return faultaddr


def readbinfile(textfile):
    '''
    Read binary file
    '''
    f = open(textfile, 'rb')
    text = f.read()
    return text


def getexnum(reporttext):
    '''
    Get the exception number by counting the number of continues
    '''
    exception = 0
    for line in reporttext.splitlines():
        n = re.match(regex['dbg_prompt'], line)
        if n:
            cdbcmd = n.group(1)
            cmds = cdbcmd.split(';')
            for cmd in cmds:
                if cmd == 'g':
                    exception = exception + 1
    return exception


def getinstraddr(reporttext):
    '''
    Find the address for the current (crashing) instruction
    '''
    instraddr = None
    for line in reporttext.splitlines():
        #print 'checking: %s' % line
        n = re.match(regex['current_instr'], line)
        if n:
            instraddr = n.group(1)
            #print 'Found instruction address: %s' % instraddr
    if not instraddr:
        for line in reporttext.splitlines():
            #No disassembly. Resort to frame 0 address
            n = re.match(regex['frame0'], line)
            if n:
                instraddr = n.group(1)
                #print 'Found instruction address: %s' % instraddr
    return instraddr


def getinstr(reporttext, instraddr):
    '''
    Find the disassembly line for the current (crashing) instruction
    '''
    for line in reporttext.splitlines():
        n = re.match(regex['current_instr'], line)
        if n:
            return n.group(3)
    return ''


def formataddr(faultaddr):
    '''
    Format a 64- or 32-bit memory address to a fixed width
    '''

    if not faultaddr:
        return
    else:
        faultaddr = faultaddr.strip()
    faultaddr = faultaddr.replace('0x', '')

    if _64bit_debugger:
        # Due to a bug in !exploitable, the Exception Faulting Address is
        # often wrong with 64-bit targets
        if len(faultaddr) < 10:
            # pad faultaddr
            faultaddr = faultaddr.zfill(16)
    else:
        if len(faultaddr) > 10:  # 0x12345678 = 10 chars
            faultaddr = faultaddr[-8:]
        elif len(faultaddr) < 10:
            # pad faultaddr
            faultaddr = faultaddr.zfill(8)

    return faultaddr


def fixefaoffset(instructionline, faultaddr):
    '''
    Adjust faulting address for instructions that use offsets
    Currently only works for instructions like CALL [reg + offset]
    '''
    global reg_set

    if '0x' not in faultaddr:
        faultaddr = '0x' + faultaddr
    instructionpieces = instructionline.split()
    for index, piece in enumerate(instructionpieces):
        if piece == 'call':
            # CALL instruction
            if len(instructionpieces) <= index + 3:
                # CALL to just a register.  No offset
                return faultaddr
            address = instructionpieces[index + 3]
            if '+' in address:
                splitaddress = address.split('+')
                reg = splitaddress[0]
                reg = reg.replace('[', '')
                if reg not in reg_set:
                    return faultaddr
                offset = splitaddress[1]
                offset = offset.replace('h', '')
                offset = offset.replace(']', '')
                if '0x' not in offset:
                    offset = '0x' + offset
                if int(offset, 16) > int(faultaddr, 16):
                    # TODO: fix up negative numbers
                    return faultaddr
                # Subtract offset to get actual interesting pattern
                faultaddr = hex(eval(faultaddr) - eval(offset))
                faultaddr = formataddr(faultaddr.replace('L', ''))
    return faultaddr


def checkreport(reportfile, crasherfile, crash_hash):
    '''
    Parse the gdb file
    '''

    global _64bit_debugger

    #print('checking %s against %s: %s' % (reportfile, crasherfile, crash_hash))
    crashid = results[crash_hash]

    reporttext = readfile(reportfile)
    current_dir = os.path.dirname(reportfile)
    exceptionnum = 0
    classification = carve(reporttext, "Classification: ", "\n")
    #print 'classification: %s' % classification
    try:
        if classification:
            # Create a new exception dictionary to add to the crash
            exception = {}
            crashid['exceptions'][exceptionnum] = exception
    except KeyError:
        # Crash ID (crash_hash) not yet seen
        # Default it to not being "really exploitable"
        crashid['reallyexploitable'] = False
        # Create a dictionary of exceptions for the crash id
        exceptions = {}
        crashid['exceptions'] = exceptions
        # Create a dictionary for the exception
        crashid['exceptions'][exceptionnum] = exception

    # Set !exploitable classification for the exception
    if classification:
        crashid['exceptions'][exceptionnum]['classification'] = classification

    shortdesc = carve(reporttext, "Short description: ", " (")
    #print 'shortdesc: %s' % shortdesc
    if shortdesc:
        # Set !exploitable Short Description for the exception
        crashid['exceptions'][exceptionnum]['shortdesc'] = shortdesc
        # Flag the entire crash ID as really exploitable if this is a good
        # exception
        crashid['reallyexploitable'] = shortdesc in re_set

    if not os.path.isfile(crasherfile):
        # Can't find the crasher file
        #print "WTF! Cannot find %s" % crasherfile
        return
    # Set the "fuzzedfile" property for the crash ID
    crashid['fuzzedfile'] = crasherfile
    # See if we're dealing with 64-bit debugger or target app
    check_64bit(reporttext)
    faultaddr = carve2(reporttext)
    #print 'faultaddr: %s' % faultaddr
    instraddr = getinstraddr(reporttext)
    #instraddr = carve(reporttext, "Instruction Address:", "\n")
    faultaddr = formataddr(faultaddr)
    instraddr = formataddr(instraddr)
    #print 'instruction address: %s' % instraddr

    # No faulting address means no crash.
    if not faultaddr:
        return

    if instraddr:
        crashid['exceptions'][exceptionnum]['pcmodule'] = pc_in_mapped_address(reporttext, instraddr)

    # Get the cdb line that contains the crashing instruction
    instructionline = getinstr(reporttext, instraddr)
    crashid['exceptions'][exceptionnum]['instructionline'] = instructionline
    if instructionline:
        faultaddr = fixefaoffset(instructionline, faultaddr)

    # Fix faulting pattern endian
    faultaddr = faultaddr.replace('0x', '')
    crashid['exceptions'][exceptionnum]['efa'] = faultaddr
    if _64bit_debugger:
        # 64-bit target app
        faultaddr = faultaddr.zfill(16)
        #print 'faultaddr: %s' % faultaddr
        efaptr = struct.unpack('<Q', binascii.a2b_hex(faultaddr))
        efapattern = hex(efaptr[0]).replace('0x', '')
        efapattern = efapattern.replace('L', '')
        efapattern = efapattern.zfill(16)
    else:
        # 32-bit target app
        faultaddr = faultaddr.zfill(8)
        efaptr = struct.unpack('<L', binascii.a2b_hex(faultaddr))
        efapattern = hex(efaptr[0]).replace('0x', '')
        efapattern = efapattern.replace('L', '')
        efapattern = efapattern.zfill(8)

    # Read in the fuzzed file
    crasherdata = readbinfile(crasherfile)

    # If there's a match, flag this exception has having Efa In File
    if binascii.a2b_hex(efapattern) in crasherdata:
        crashid['exceptions'][exceptionnum]['EIF'] = True
    else:
        crashid['exceptions'][exceptionnum]['EIF'] = False


def findgdbs(tld):
    # Walk the results directory
    for root, dirs, files in os.walk(tld):
        crash_hash = os.path.basename(root)
        # Only use directories that are hashes
        # if "0x" in crash_hash:
            # Create dictionary for hashes in results dictionary
        hash_dict = {}
        hash_dict['hash'] = crash_hash
        results[crash_hash] = hash_dict
        crasherfile = ''
        # Check each of the files in the hash directory
        for current_file in files:
            # Go through all of the .gdb files and parse them
            if regex['gdb_report'].match(current_file):
                #print 'checking %s' % current_file
                gdbdict = {}
                gdbfile = os.path.join(root, current_file)
                crasherfile = gdbfile.replace('.gdb', '')
                #crasherfile = os.path.join(root, crasherfile)
                gdbdict['gdbfile'] = gdbfile
                gdbdict['crasherfile'] = crasherfile
                gdbdict['crash_hash'] = crash_hash
#               print 'appending %s' % gdbdict
                gdblist.append(gdbdict)
    return gdblist


def parsegdbs(gdblist):
    for gdb in gdblist:
        checkreport(gdb['gdbfile'], gdb['crasherfile'], gdb['crash_hash'])


def printreport():
    sorted_crashes = sorted(scoredcrashes.iteritems(), key=lambda(k, v): (v, k))

    for crashes in sorted_crashes:
        crasher = crashes[0]
        score = crashes[1]
        print '\n%s - Exploitability rank: %s' % (crasher, score)
        print 'Fuzzed file: %s' % results[crasher]['fuzzedfile']
        for exception in results[crasher]['exceptions']:
            shortdesc = results[crasher]['exceptions'][exception]['shortdesc']
            eiftext = ''
            efa = '0x' + results[crasher]['exceptions'][exception]['efa']
            if results[crasher]['exceptions'][exception]['EIF']:
                eiftext = " *** Byte pattern is in fuzzed file! ***"
            print 'exception %s: %s accessing %s  %s' % (exception, shortdesc, efa, eiftext)
            if results[crasher]['exceptions'][exception]['instructionline']:
                print results[crasher]['exceptions'][exception]['instructionline']
            module = results[crasher]['exceptions'][exception]['pcmodule']
            if module == 'unloaded':
                if not ignorejit:
                    print 'Instruction pointer is not in a loaded module!'
            else:
                print 'Code executing in: %s' % module


def main():
    # If user doesn't specify a directory to crawl, use "results"
    global ignorejit
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option('-d', '--dir',
                      help='directory to look for results in. Default is "results"',
                      dest='resultsdir', default='../results')
    parser.add_option('-j', '--ignorejit', dest='ignorejit',
                      action='store_true',
                      help='Ignore PC in unmapped module (JIT)')
    (options, args) = parser.parse_args()
    ignorejit = options.ignorejit
    tld = options.resultsdir
    if not os.path.isdir(tld):
        tld = 'results'
    if not os.path.isdir(tld):
        # Probably using FOE 1.0, which defaults to "crashers" for output
        tld = 'crashers'
    gdblist = findgdbs(tld)
    parsegdbs(gdblist)
    score_reports(results, scoredcrashes, ignorejit, re_set)
    printreport()

if __name__ == '__main__':
    main()
