#!/bin/sh

##############################################################################
# Use of the CERT Basic Fuzzing Framework and related source code is subject
# to the terms of the following licenses:
# 
# GNU Public License (GPL) Rights pursuant to Version 2, June 1991
# Government Purpose License Rights (GPLR) pursuant to DFARS 252.227.7013
# 
# NO WARRANTY
# 
# ANY INFORMATION, MATERIALS, SERVICES, INTELLECTUAL PROPERTY OR OTHER
# PROPERTY OR RIGHTS GRANTED OR PROVIDED BY CARNEGIE MELLON UNIVERSITY
# PURSUANT TO THIS LICENSE (HEREINAFTER THE "DELIVERABLES") ARE ON AN
# "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED AS TO ANY MATTER INCLUDING, BUT NOT
# LIMITED TO, WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE,
# MERCHANTABILITY, INFORMATIONAL CONTENT, NONINFRINGEMENT, OR ERROR-FREE
# OPERATION. CARNEGIE MELLON UNIVERSITY SHALL NOT BE LIABLE FOR INDIRECT,
# SPECIAL OR CONSEQUENTIAL DAMAGES, SUCH AS LOSS OF PROFITS OR INABILITY
# TO USE SAID INTELLECTUAL PROPERTY, UNDER THIS LICENSE, REGARDLESS OF
# WHETHER SUCH PARTY WAS AWARE OF THE POSSIBILITY OF SUCH DAMAGES.
# LICENSEE AGREES THAT IT WILL NOT MAKE ANY WARRANTY ON BEHALF OF
# CARNEGIE MELLON UNIVERSITY, EXPRESS OR IMPLIED, TO ANY PERSON
# CONCERNING THE APPLICATION OF OR THE RESULTS TO BE OBTAINED WITH THE
# DELIVERABLES UNDER THIS LICENSE.
# 
# Licensee hereby agrees to defend, indemnify, and hold harmless Carnegie
# Mellon University, its trustees, officers, employees, and agents from
# all claims or demands made against them (and any related losses,
# expenses, or attorney's fees) arising out of, or relating to Licensee's
# and/or its sub licensees' negligent use or willful misuse of or
# negligent conduct or willful misconduct regarding the Software,
# facilities, or other rights or assistance granted by Carnegie Mellon
# University under this License, including, but not limited to, any
# claims of product liability, personal injury, death, damage to
# property, or violation of any laws or regulations.
# 
# Carnegie Mellon University Software Engineering Institute authored
# documents are sponsored by the U.S. Department of Defense under
# Contract F19628-00-C-0003. Carnegie Mellon University retains
# copyrights in all material produced under this contract. The U.S.
# Government retains a non-exclusive, royalty-free license to publish or
# reproduce these documents, or allow others to do so, for U.S.
# Government purposes only pursuant to the copyright license under the
# contract clause at 252.227.7013.
##############################################################################


# contains(string, substring)
#
# Returns 0 if the specified string contains the specified substring,
# otherwise returns 1.
contains() {
    string="$1"
    substring="$2"
    if test "${string#*$substring}" != "$string"
    then
        return 0    # $substring is in $string
    else
        return 1    # $substring is not in $string
    fi
}


scriptlocation=`echo "$(cd "$(dirname "$0")"; pwd)/"`
echo Script location: $scriptlocation/bff.py
platform=`uname -a`
PINURL=https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.0-76991-gcc-linux.tar.gz
if ( contains "$platform" "Darwin Kernel Version 11" ); then
    mypython="/Library/Frameworks/Python.framework/Versions/2.7/bin/python"
else
    mypython="python"
fi


# Prevent creation of huge files
ulimit -f 1048576

# Enable reasonably-sized core dumps
ulimit -c 4096

if ( contains "$platform" "Linux" ); then
    if [ ! -f ~/pin/pin ]; then
        mkdir -p ~/fuzzing
        echo PIN not detected. Downloading...
        tarball=~/fuzzing/`basename $PINURL`
        pindir=`basename $tarball .tar.gz`
        wget --tries=1 $PINURL -O $tarball
        if [ -f $tarball ]; then      
            tar xzvf $tarball -C ~
            mv ~/$pindir ~/pin
        else
            echo Error retrieving PIN
        fi
    fi
    
    if [ ! -f ~/pintool/calltrace.so ]; then
        echo Building calltrace pintool...
        cp -au $scriptlocation/pintool ~
        cd ~/pintool
        $mypython make.py
    fi
    
    if [ ~/pintool/calltrace.cpp -ot $scriptlocation/pintool/calltrace.cpp ]; then
        echo Updating calltrace pintool...
        cp -au $scriptlocation/pintool ~
        cd ~/pintool
        $mypython make.py
    fi        
fi

cd $scriptlocation

echo "Using python interpreter: $mypython"
if [ -f "$scriptlocation/bff.py" ]; then
    $mypython $scriptlocation/bff.py "$@"
else
    read -p "Cannot find $scriptlocation/bff.py Please verify script locations."
fi

