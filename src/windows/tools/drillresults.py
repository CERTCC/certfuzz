'''
This script looks for interesting crashes and rate them by potential exploitability
'''

import os
import struct
import binascii
import re
from optparse import OptionParser
import StringIO
import zipfile
import cPickle as pickle

regex = {
        'first_msec': re.compile('^sf_.+-\w+-0x.+.-[A-Z]'),
        'msec_report': re.compile('.+.msec$'),
        'regs1': re.compile('^eax=.+'),
        'regs2': re.compile('^eip=.+'),
        '64bit_debugger': re.compile('^Microsoft.*AMD64$'),
        'syswow64': re.compile('ModLoad:.*syswow64.*', re.IGNORECASE),
        'mapped_address': re.compile('^ModLoad: ([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(.+)'),
        'mapped_address64': re.compile('^ModLoad: ([0-9a-fA-F]+`[0-9a-fA-F]+)\s+([0-9a-fA-F]+`[0-9a-fA-F]+)\s+(.+)'),
        'syswow64': re.compile('ModLoad:.*syswow64.*', re.IGNORECASE),
        'dbg_prompt': re.compile('^[0-9]:[0-9][0-9][0-9]> (.*)'),
        'wow64_dbg_prompt': re.compile('^[0-9]:[0-9][0-9][0-9]:x86> (.*)'),
        }

registers = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi',
             'edi', 'eip')

registers64 = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi',
               'rdi', 'rip', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13',
               'r14', 'r15')

# These !exploitable short descriptions indicate a very interesting crash
really_exploitable = [
                      'ReadAVonIP',
                      'TaintedDataControlsCodeFlow',
                      'ReadAVonControlFlow',
                      'DEPViolation',
                      'IllegalInstruction',
                      'PrivilegedInstruction',
                      ]
reg_set = set(registers)
reg64_set = set(registers64)
re_set = set(really_exploitable)

results = {}
cached_results = {}
scoredcrashes = {}
regdict = {}
mseclist = []
_64bit_debugger = False
wow64_app = False
ignorejit = False
pickle_file = os.path.join('fuzzdir', 'drillresults.pkl')


def check_64bit(reporttext):
    '''
    Check if the debugger and target app are 64-bit
    '''
    global _64bit_debugger
    global wow64_app
    for line in reporttext.splitlines():
        n = re.match(regex['64bit_debugger'], line)
        if n:
            _64bit_debugger = True
        if _64bit_debugger:
            n = re.match(regex['syswow64'], line)
            if n:
                wow64_app = True


def pc_in_mapped_address(reporttext, instraddr):
    '''
    Check if the instruction pointer is in a loaded module
    '''
    global _64bit_debugger
    global wow64_app
    ma_regex = 'mapped_address'
    mapped_module = 'unloaded'
    if _64bit_debugger:
        ma_regex = 'mapped_address64'

    instraddr = instraddr.replace('`', '')
    instraddr = int(instraddr, 16)
    for line in reporttext.splitlines():
        n = re.match(regex[ma_regex], line)
        if n:
            # Strip out backticks present on 64-bit systems
            begin_address = int(n.group(1).replace('`', ''), 16)
            end_address = int(n.group(2).replace('`', ''), 16)
            if begin_address < instraddr < end_address:
                mapped_module = n.group(3)
    return mapped_module


def fixefabug(reporttext, instraddr, faultaddr):
    '''
    !exploitable often reports an incorrect EFA for 64-bit targets.
    If we're dealing with a 64-bit target, we can second-guess the reported EFA
    '''
    instructionline = getinstr(reporttext, instraddr)
    if not instructionline or "=" not in instructionline:
        # Nothing to fix
        return faultaddr
    if 'ds:' in instructionline:
        # There's a target address in the msec file
        if '??' in instructionline:
            # The AV is on dereferencing where to call
            ds = carve(instructionline, "ds:", "=")
        else:
            # The AV is on accessing the code location
            ds = instructionline.split("=")[-1]
    else:
        # AV must be on current instruction
        ds = instructionline.split(' ')[0]
    if ds:
        faultaddr = ds.replace('`', '')
    return faultaddr


def readfile(textfile):
    '''
    Read text file
    '''
    f = open(textfile, 'r')
    text = f.read()
    f.close()
    return text


def readbinfile(inputfile):
    '''
    Read binary file
    '''
    f = open(inputfile, 'rb')
    filebytes = f.read()
    # For zip files, return the uncompressed bytes
    file_like_content = StringIO.StringIO(filebytes)
    if zipfile.is_zipfile(file_like_content):
        # Make sure that it's not an embedded zip
        # (e.g. a DOC file from Office 2007)
        file_like_content.seek(0)
        zipmagic = file_like_content.read(2)
        if zipmagic == 'PK':
            try:
                # The file begins with the PK header
                z = zipfile.ZipFile(file_like_content, 'r')
                for filename in z.namelist():
                    try:
                        filebytes += z.read(filename)
                    except:
                        pass
            except:
                # If the zip container is fuzzed we may get here
                pass
    file_like_content.close()
    f.close
    return filebytes


def carve(string, token1, token2):
    startindex = string.find(token1)
    if startindex == -1:
        # can't find token1
        return ""
    startindex = startindex + len(token1)
    endindex = string.find(token2, startindex)
    if endindex == -1:
        # can't find token2
        return ""
    return string[startindex:endindex]


# Todo: fix this up.  Was added to bring gdb support
def carve2(string):
    delims = [("Exception Faulting Address: ", "\n"),
              ("si_addr:$2 = (void *)", "\n")]
    for token1, token2 in delims:
        startindex = string.find(token1)
        if startindex == -1:
            # can't find token1
            continue
        startindex = startindex + len(token1)
        endindex = string.find(token2, startindex)
        return string[startindex:endindex]


def getexnum(reporttext):
    '''
    Get the exception number by counting the number of continues
    '''
    global wow64_app

    if wow64_app:
        dbg_prompt = 'wow64_dbg_prompt'
    else:
        dbg_prompt = 'dbg_prompt'
    exception = 0
    for line in reporttext.splitlines():
        n = re.match(regex[dbg_prompt], line)
        if n:
            cdbcmd = n.group(1)
            cmds = cdbcmd.split(';')
            for cmd in cmds:
                if cmd == 'g':
                    exception = exception + 1
    return exception


def getregs(reporttext):
    '''
    Populate the register dictionary with register values at crash
    '''
    for line in reporttext.splitlines():
        if regex['regs1'].match(line) or regex['regs2'].match(line):
            regs1 = line.split()
            for reg in regs1:
                if "=" in reg:
                    splitreg = reg.split("=")
                    regdict[splitreg[0]] = splitreg[1]


def getinstr(reporttext, instraddr):
    '''
    Find the disassembly line for the current (crashing) instruction
    '''
    regex = re.compile('^%s\s.+.+\s+' % instraddr)
    for line in reporttext.splitlines():
        if regex.match(line):
            return line


def formataddr(faultaddr):
    '''
    Format a 64- or 32-bit memory address to a fixed width
    '''
    global _64bit_debugger
    global wow64_app

    if not faultaddr:
        return
    else:
        faultaddr = faultaddr.strip()
    faultaddr = faultaddr.replace('0x', '')

    if _64bit_debugger and not wow64_app:
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


def ratchetscore(crasher, score):
    '''
    Only allow a crasher to increase score
    '''
    try:
        currentscore = scoredcrashes[crasher]
    except KeyError:
        currentscore = 100
    if score < currentscore:
        scoredcrashes[crasher] = score


def fixefaoffset(instructionline, faultaddr):
    '''
    Adjust faulting address for instructions that use offsets
    Currently only works for instructions like CALL [reg + offset]
    '''
    global reg_set
    if _64bit_debugger and not wow64_app:
        reg_set = reg64_set

    if '0x' not in faultaddr:
        faultaddr = '0x' + faultaddr
    instructionpieces = instructionline.split()
    if '??' not in instructionpieces[-1]:
        # The av is on the address of the code called, not the address
        # of the call
        return faultaddr
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
    Parse the msec file
    '''
    global _64bit_debugger
    global wow64_app
    global cached_results

    if cached_results:
        if cached_results.get(crash_hash):
            results[crash_hash] = cached_results[crash_hash]
            return

    crashid = results[crash_hash]

    if crasherfile == '':
        # Old FOE version that didn't do multiple exceptions or rename msec
        # file with exploitability
        crasherfile, reportfileext = os.path.splitext(reportfile)

    reporttext = readfile(reportfile)
    getregs(reporttext)
    current_dir = os.path.dirname(reportfile)
    exceptionnum = getexnum(reporttext)
    classification = carve(reporttext, "Exploitability Classification: ", "\n")
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

    shortdesc = carve(reporttext, "Short Description: ", "\n")
    if shortdesc:
        # Set !exploitable Short Description for the exception
        crashid['exceptions'][exceptionnum]['shortdesc'] = shortdesc
        if shortdesc in re_set:
            # Flag the entire crash ID as really exploitable if this is a good
            # exception
            crashid['reallyexploitable'] = True
    # Check if the expected crasher file (fuzzed file) exists
    if not os.path.isfile(crasherfile):
        # It's not there, so try to extract the filename from the cdb
        # commandline
        commandline = carve(reporttext, "CommandLine: ", "\n")
        args = commandline.split()
        for arg in args:
            if "sf_" in arg:
                crasherfile = os.path.basename(arg)
                if "-" in crasherfile:
                    # FOE 2.0 verify mode puts a '-<iteration>' part on the
                    # filename when invoking cdb, however the resulting file
                    # is really just 'sf_<hash>.<ext>'
                    fileparts = crasherfile.split('-')
                    m = re.search('\..+', fileparts[1])
                    # Recreate the original file name, minus the iteration
                    crasherfile = os.path.join(current_dir, fileparts[0] + m.group(0))
                else:
                    crasherfile = os.path.join(current_dir, crasherfile)
    if not os.path.isfile(crasherfile):
        # Can't find the crasher file
        return
    # Set the "fuzzedfile" property for the crash ID
    crashid['fuzzedfile'] = crasherfile
    # See if we're dealing with 64-bit debugger or target app
    check_64bit(reporttext)
    faultaddr = carve2(reporttext)
    instraddr = carve(reporttext, "Instruction Address:", "\n")
    faultaddr = formataddr(faultaddr)
    instraddr = formataddr(instraddr)

    # No faulting address means no crash.
    if not faultaddr or not instraddr:
        return

    if _64bit_debugger and not wow64_app and instraddr:
        # Put backtick into instruction address for pattern matching
        instraddr = ''.join([instraddr[:8], '`', instraddr[8:]])
        if shortdesc != 'DEPViolation':
            faultaddr = fixefabug(reporttext, instraddr, faultaddr)


#    pc_module = pc_in_mapped_address(reporttext, instraddr)
    try:
        crashid['exceptions'][exceptionnum]['pcmodule'] = pc_in_mapped_address(reporttext, instraddr)
    except:
        print reporttext 
    # Get the cdb line that contains the crashing instruction
    instructionline = getinstr(reporttext, instraddr)
    crashid['exceptions'][exceptionnum]['instructionline'] = instructionline
    if instructionline:
        faultaddr = fixefaoffset(instructionline, faultaddr)

    # Fix faulting pattern endian
    faultaddr = faultaddr.replace('0x', '')
    crashid['exceptions'][exceptionnum]['efa'] = faultaddr
    if _64bit_debugger and not wow64_app:
        # 64-bit target app
        faultaddr = faultaddr.zfill(16)
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


def findmsecs(tld):
    # Walk the results directory
    for root, dirs, files in os.walk(tld):
        crash_hash = os.path.basename(root)
        # Only use directories that are hashes
        if "0x" in crash_hash:
            # Create dictionary for hashes in results dictionary
            hash_dict = {}
            hash_dict['hash'] = crash_hash
            results[crash_hash] = hash_dict
            crasherfile = ''
            # Check each of the files in the hash directory
            for current_file in files:
                # If it's exception #0, strip out the exploitability part of
                # the file name. This gives us the crasher file name
                if regex['first_msec'].match(current_file):
                    crasherfile, reportfileext = os.path.splitext(current_file)
                    crasherfile = crasherfile.replace('-EXP', '')
                    crasherfile = crasherfile.replace('-PEX', '')
                    crasherfile = crasherfile.replace('-PNE', '')
                    crasherfile = crasherfile.replace('-UNK', '')
            for current_file in files:
                # Go through all of the .msec files and parse them
                if regex['msec_report'].match(current_file):
                    msecdict = {}
                    msecfile = os.path.join(root, current_file)
                    if crasherfile and root not in crasherfile:
                        crasherfile = os.path.join(root, crasherfile)
                    msecdict['msecfile'] = msecfile
                    msecdict['crasherfile'] = crasherfile
                    msecdict['crash_hash'] = crash_hash
                    mseclist.append(msecdict)
    return mseclist


def parsemsecs(mseclist):
    for msec in mseclist:
        checkreport(msec['msecfile'], msec['crasherfile'], msec['crash_hash'])


def score_reports():
    # Assign a ranking to each crash report.  The lower the rank, the higher
    # the exploitability
    if results:
        print "--- Interesting crashes ---\n"
        # For each of the crash ids in the results dictionary, apply ranking
        for crasher in results:
            try:
                if results[crasher]['reallyexploitable'] == True:
                    # The crash summery is a very interesting one
                    for exception in results[crasher]['exceptions']:
                        module = results[crasher]['exceptions'][exception]['pcmodule']
                        if module == 'unloaded' and not ignorejit:
                            # EIP is not in a loaded module
                            ratchetscore(crasher, 20)
                        if results[crasher]['exceptions'][exception]['shortdesc'] in re_set:
                            efa = '0x' + results[crasher]['exceptions'][exception]['efa']
                            if results[crasher]['exceptions'][exception]['EIF']:
                                # The faulting address pattern is in the fuzzed file
                                if '0x000000' in efa:
                                    # Faulting address is near null
                                    ratchetscore(crasher, 30)
                                elif '0x0000' in efa:
                                    # Faulting address is somewhat near null
                                    ratchetscore(crasher, 20)
                                elif '0xffff' in efa:
                                    # Faulting address is likely a negative number
                                    ratchetscore(crasher, 20)
                                else:
                                    # Faulting address has high entropy.  Most exploitable.
                                    ratchetscore(crasher, 10)
                            else:
                                # The faulting address pattern is not in the fuzzed file
                                ratchetscore(crasher, 40)
                else:
                    # The crash summary isn't necessarily interesting
                    for exception in results[crasher]['exceptions']:
                        efa = '0x' + results[crasher]['exceptions'][exception]['efa']
                        module = results[crasher]['exceptions'][exception]['pcmodule']
                        if module == 'unloaded' and not ignorejit:
                            ratchetscore(crasher, 20)
                        elif module.lower() == 'ntdll.dll' or 'msvcr' in module.lower():
                            #likely heap corruption.  Exploitable, but difficult
                            ratchetscore(crasher, 45)
                        elif '0x00120000' in efa or '0x00130000' in efa or '0x00140000' in efa:
                            #non-continued potential stack buffer overflow
                            ratchetscore(crasher, 40)
                        elif results[crasher]['exceptions'][exception]['EIF']:
                            # The faulting address pattern is in the fuzzed file
                            if '0x000000' in efa:
                                # Faulting address is near null
                                ratchetscore(crasher, 70)
                            elif '0x0000' in efa:
                                # Faulting address is somewhat near null
                                ratchetscore(crasher, 60)
                            elif '0xffff' in efa:
                                # Faulting address is likely a negative number
                                ratchetscore(crasher, 60)
                            else:
                                # Faulting address has high entropy.
                                ratchetscore(crasher, 50)
            except KeyError:
                print "Error scoring crash %s" % crasher
                continue


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
            print results[crasher]['exceptions'][exception]['instructionline']
            module = results[crasher]['exceptions'][exception]['pcmodule']
            if module == 'unloaded':
                if not ignorejit:
                    print 'Instruction pointer is not in a loaded module!'
            else:
                print 'Code executing in: %s' % module

def loadcached(pkl_filename):
    try:
        with open(pkl_filename, 'rb') as pkl_file:
            return pickle.load(pkl_file)
    except IOError:
        # No cached results
        pass


def cache_results(pkl_filename):
    pkldir = os.path.dirname(pkl_filename)
    if not os.path.exists(pkldir):
        os.makedirs(pkldir)
    with open(pkl_filename, 'wb') as pkl_file:
        pickle.dump(results, pkl_file, -1)


def main():
    # If user doesn't specify a directory to crawl, use "results"
    global ignorejit
    global cached_results
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option('-d', '--dir',
                      help='directory to look for results in. Default is "results"',
                      dest='resultsdir', default='../results')
    parser.add_option('-j', '--ignorejit', dest='ignorejit',
                      action='store_true',
                      help='Ignore PC in unmapped module (JIT)')
    parser.add_option('-f', '--force', dest='force',
                      action='store_true',
                      help='Force recalculation of results')
    (options, args) = parser.parse_args()
    ignorejit = options.ignorejit
    tld = options.resultsdir
    if not os.path.isdir(tld):
        tld = 'results'
    if not os.path.isdir(tld):
        # Probably using FOE 1.0, which defaults to "crashers" for output
        tld = 'crashers'
    mseclist = findmsecs(tld)
    if not options.force:
        cached_results = loadcached(pickle_file)
    parsemsecs(mseclist)
    score_reports()
    printreport()
    cache_results(pickle_file)

if __name__ == '__main__':
    main()
