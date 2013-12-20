tell application "Finder"
	set sel to selection
	if (count sel) > 0 then
		set myTarget to item 1 of sel
	else if (count window) > 0 then
		set myTarget to target of window 1
	else
		set myTarget to path to desktop folder
	end if
	my openTerminal(myTarget)
end tell

on openTerminal(location)
	set location to location as alias
	set the_path to POSIX path of location
	repeat until the_path ends with "/"
		set the_path to text 1 thru -2 of the_path
	end repeat
	
	set cmd to "cd ~/bff && echo $'\\ec' && echo \"***** Welcome to the CERT BFF! *****

Current working directory: $PWD
Current target commandline: `egrep -m1 '^cmdline' conf.d/bff.cfg | sed 's/cmdline=//'`
Current output directory: `egrep -m1 '^output_dir' conf.d/bff.cfg | sed 's/output_dir=//'`

Please see the README file for details on use.

Run ./batch.sh to begin fuzzing.

\""
	
	tell application "System Events" to set terminalIsRunning to exists application process "Terminal"
	
	tell application "Terminal"
		activate
		if terminalIsRunning is true then
			do script with command cmd
		else
			do script with command cmd in window 1
		end if
	end tell
end openTerminal