#!/bin/sh

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

platform=`uname -a`
echo "Exploitability Summary for campaign thus far:"
if ( contains "$platform" "Darwin" ); then
	exploitable=`find -L ~/bff/results -name '*.cw' | grep crashers | xargs grep is_exploitable=y | awk -Fcrashers/ '{print $2}' | awk -F/ '{print $1}' | sort | uniq | wc -l`
	total=`find -L ~/bff/results -name '*.cw' | grep crashers | grep -v gmalloc | wc -l`
	not_exploitable=$(expr $total - $exploitable)
	echo 	$exploitable Exploitable
	echo 	$not_exploitable Unknown
    echo    $total Total
else
	find -L ~/bff/results -name '*.gdb' | grep crashers | xargs grep -h "Exploitability Classification" | cut -d" " -f3 | sort | uniq -c
    echo `find -L ~/bff/results -name '*.gdb' | grep crashers | wc -l` TOTAL
fi