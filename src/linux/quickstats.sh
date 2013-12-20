#!/bin/bash

platform=`uname -a`
echo "Exploitability Summary for campaign thus far:"
if [[ "$platform" =~ "Darwin" ]]; then
	exploitable=`find ~/results/crashers -name '*.cw' | xargs grep is_exploitable=y | awk -Fcrashers/ '{print $2}' | awk -F/ '{print $1}' | sort | uniq | wc -l`
	total=`find ~/results/crashers -type d | wc -l`
	let total-=1
	not_exploitable=$(expr $total - $exploitable)
	echo 	$exploitable Exploitable
	echo 	$not_exploitable Unknown
    echo    $total Total
else
	find ~/results/crashers -name '*.gdb' | xargs grep -h "Exploitability Classification" | cut -d" " -f3 | sort | uniq -c
    echo `find ~/results/crashers -type d | tail -n +2 | wc -l` TOTAL
fi