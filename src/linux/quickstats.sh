#!/bin/bash

platform=`uname -a`
echo "Exploitability Summary for campaign thus far:"
if [[ "$platform" =~ "Darwin" ]]; then
	exploitable=`find -L ~/results -name '*.cw' | grep crashers | xargs grep is_exploitable=y | awk -Fcrashers/ '{print $2}' | awk -F/ '{print $1}' | sort | uniq | wc -l`
	total=`find -L ~/results -name '*.cw' | grep crashers | grep -v gmalloc | wc -l`
	not_exploitable=$(expr $total - $exploitable)
	echo 	$exploitable Exploitable
	echo 	$not_exploitable Unknown
    echo    $total Total
else
	find -L ~/results -name '*.gdb' | grep crashers | xargs grep -h "Exploitability Classification" | cut -d" " -f3 | sort | uniq -c
    echo `find -L ~/results -name '*.gdb' | grep crashers | wc -l` TOTAL
fi