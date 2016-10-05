'''
Created on Jan 14, 2016

@author: adh
'''
import shlex


def get_command_args_list(cmd_template, infile, posix=True):
    '''
    Given a command template and infile, will substitute infile into the
    template, and return both the complete string and its component parts
    as returned by shlex.split. The optional posix parameter is passed to
    shlex.split (defaults to true).
    :param cmd_template: a string.Template object containing "$SEEDFILE"
    :param infile: the string to substitute for "$SEEDFILE" in cmd_template
    :param posix: (optional) passed through to shlex.split
    '''
    cmd = cmd_template.substitute(SEEDFILE=infile)
    cmdlist = shlex.split(cmd, posix=posix)
    return cmd, cmdlist