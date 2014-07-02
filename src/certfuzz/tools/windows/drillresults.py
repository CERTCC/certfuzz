'''
This script looks for interesting crashes and rate them by potential exploitability
'''

import os
import struct
import binascii
import re
import StringIO
import zipfile

from certfuzz.tools.common.drillresults import read_file, carve, carve2, \
    is_number, reg_set, reg64_set, ResultDriller, parse_args

regex = {
        '64bit_debugger': re.compile('^Microsoft.*AMD64$'),
        'first_msec': re.compile('^sf_.+-\w+-0x.+.-[A-Z]'),
        'mapped_address': re.compile('^ModLoad: ([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(.+)'),
        'mapped_address64': re.compile('^ModLoad: ([0-9a-fA-F]+`[0-9a-fA-F]+)\s+([0-9a-fA-F]+`[0-9a-fA-F]+)\s+(.+)'),
        'msec_report': re.compile('.+.msec$'),
        'regs1': re.compile('^eax=.+'),
        'regs2': re.compile('^eip=.+'),
        'syswow64': re.compile('ModLoad:.*syswow64.*', re.IGNORECASE),
        }


# These !exploitable short descriptions indicate a very interesting crash
really_exploitable = [
                      'ReadAVonIP',
                      'TaintedDataControlsCodeFlow',
                      'ReadAVonControlFlow',
                      'DEPViolation',
                      'IllegalInstruction',
                      'PrivilegedInstruction',
                      ]

re_set = set(really_exploitable)


def fix_efa_bug(reporttext, instraddr, faultaddr):
    '''
    !exploitable often reports an incorrect EFA for 64-bit targets.
    If we're dealing with a 64-bit target, we can second-guess the reported EFA
    '''
    instructionline = get_instr(reporttext, instraddr)
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


def read_bin_file(inputfile):
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


def get_ex_num(reporttext, wow64_app):
    '''
    Get the exception number by counting the number of continues
    '''
    if wow64_app:
        pattern = re.compile('^[0-9]:[0-9][0-9][0-9]:x86> (.*)')
    else:
        pattern = re.compile('^[0-9]:[0-9][0-9][0-9]> (.*)')

    exception = 0

    for line in reporttext.splitlines():
        n = re.match(pattern, line)
        if n:
            cdbcmd = n.group(1)
            cmds = cdbcmd.split(';')
            exception += cmds.count('g')

    return exception


def get_regs(reporttext):
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


def get_instr(reporttext, instraddr):
    '''
    Find the disassembly line for the current (crashing) instruction
    '''
    regex = re.compile('^%s\s.+.+\s+' % instraddr)
    for line in reporttext.splitlines():
        n = regex.match(line)
        if n:
            return line




def fix_efa_offset(instructionline, faultaddr, _64bit_debugger, wow64_app):
    '''
    Adjust faulting address for instructions that use offsets
    Currently only works for instructions like CALL [reg + offset]
    '''
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
                if is_number(offset):
                    if '0x' not in offset:
                        offset = '0x' + offset
                    if int(offset, 16) > int(faultaddr, 16):
                        # TODO: fix up negative numbers
                        return faultaddr
                    # Subtract offset to get actual interesting pattern
                    faultaddr = hex(eval(faultaddr) - eval(offset))
                    faultaddr = format_addr(faultaddr.replace('L', ''))
    return faultaddr

def WindowsResultDriller(ResultDriller):
    # These !exploitable short descriptions indicate a very interesting crash
    really_exploitable = [
                      'ReadAVonIP',
                      'TaintedDataControlsCodeFlow',
                      'ReadAVonControlFlow',
                      'DEPViolation',
                      'IllegalInstruction',
                      'PrivilegedInstruction',
                      ]

    def __init__(self, ignore_jit=False, base_dir='../results', force_reload=False):
        ResultDriller.__init__(self, ignore_jit, base_dir, force_reload)
        self.wow64_app = False

    def _platform_find_dbg_output(self, crash_hash, files, root):
        if "0x" in crash_hash:
            # Create dictionary for hashes in results dictionary
            hash_dict = {}
            hash_dict['hash'] = crash_hash
            self.results[crash_hash] = hash_dict
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
                    msecfile = os.path.join(root, current_file)
                    if crasherfile and root not in crasherfile:
                        crasherfile = os.path.join(root, crasherfile)
                    dbg_tuple = (msecfile, crasherfile, crash_hash)
                    self.dbg_out.append(dbg_tuple)

    def check_64bit(self, reporttext):
        '''
        Check if the debugger and target app are 64-bit
        '''
        for line in reporttext.splitlines():
            n = re.match(regex['64bit_debugger'], line)
            if n:
                self._64bit_debugger = True

            if self._64bit_debugger:
                n = re.match(regex['syswow64'], line)
                if n:
                    self.wow64_app = True

    def _check_report(self, reportfile, crasherfile, crash_hash, cached_results):
        '''
        Parse the msec file
        '''
        if cached_results:
            if cached_results.get(crash_hash):
                self.results[crash_hash] = cached_results[crash_hash]
                return

        crashid = self.results[crash_hash]

        if crasherfile == '':
            # Old FOE version that didn't do multiple exceptions or rename msec
            # file with exploitability
            crasherfile, reportfileext = os.path.splitext(reportfile)

        reporttext = read_file(reportfile)
        get_regs(reporttext)
        current_dir = os.path.dirname(reportfile)
        exceptionnum = get_ex_num(reporttext, self.wow64_app)
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
            # Flag the entire crash ID as really exploitable if this is a good
            # exception
            crashid['reallyexploitable'] = shortdesc in re_set
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
        self.check_64bit(reporttext)
        faultaddr = carve2(reporttext)
        instraddr = carve(reporttext, "Instruction Address:", "\n")
        faultaddr = self.format_addr(faultaddr)
        instraddr = self.format_addr(instraddr)

        # No faulting address means no crash.
        if not faultaddr or not instraddr:
            return

        if self._64bit_debugger and not self.wow64_app and instraddr:
            # Put backtick into instruction address for pattern matching
            instraddr = ''.join([instraddr[:8], '`', instraddr[8:]])
            if shortdesc != 'DEPViolation':
                faultaddr = fix_efa_bug(reporttext, instraddr, faultaddr)

    #    pc_module = pc_in_mapped_address(reporttext, instraddr)
        crashid['exceptions'][exceptionnum]['pcmodule'] = pc_in_mapped_address(reporttext, instraddr, _64bit_debugger)

        # Get the cdb line that contains the crashing instruction
        instructionline = get_instr(reporttext, instraddr)
        crashid['exceptions'][exceptionnum]['instructionline'] = instructionline
        if instructionline:
            faultaddr = fix_efa_offset(instructionline, faultaddr, _64bit_debugger, wow64_app)

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
        crasherdata = read_bin_file(crasherfile)

        # If there's a match, flag this exception has having Efa In File
        if binascii.a2b_hex(efapattern) in crasherdata:
            crashid['exceptions'][exceptionnum]['EIF'] = True
        else:
            crashid['exceptions'][exceptionnum]['EIF'] = False

    def format_addr(self, faultaddr):
        '''
        Format a 64- or 32-bit memory address to a fixed width
        '''
        if not faultaddr:
            return

        faultaddr = faultaddr.strip().replace('0x', '')

        if self._64bit_debugger and not self.wow64_app:
            # Due to a bug in !exploitable, the Exception Faulting Address is
            # often wrong with 64-bit targets
            if len(faultaddr) < 10:
                # pad faultaddr
                return faultaddr.zfill(16)

        if len(faultaddr) > 10:
            # 0x12345678 = 10 chars
            return faultaddr[-8:]

        if len(faultaddr) < 10:
            # pad faultaddr
            return faultaddr.zfill(8)

    def pc_in_mapped_address(self, reporttext, instraddr):
        '''
        Check if the instruction pointer is in a loaded module
        '''
        ma_regex = 'mapped_address'
        mapped_module = 'unloaded'
        if self._64bit_debugger:
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


def main():
    options = parse_args()
    with WindowsResultDriller(ignore_jit=options.ignorejit,
                         base_dir=options.resultsdir) as rd:
        rd.drill_results()

if __name__ == '__main__':
    main()
