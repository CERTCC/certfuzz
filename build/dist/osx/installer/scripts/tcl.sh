#!/bin/sh

pkgdir="$1"
osxver=`uname -a | awk '{print $3}' | awk -F. '{print $1}'`                                  
echo $osxver                                                                                 
                                                                                             
if (( "$osxver" < "11" )); then
  tclpath="/Library/Frameworks/Tcl.framework/Versions/8.4/tcl"
  tclpkg='ActiveTcl-8.4.pkg'                                                               
else
  tclpath="/Library/Frameworks/Tcl.framework/Versions/8.5/tcl"                               
  tclpkg='ActiveTcl-8.5.pkg'                                                            
fi

installdir=`echo $pkgdir | xargs -Ix dirname "x"`

if [[ ! -f $tclpath ]]; then                                                         
  if [ -d "$installdir/pkgs/$tclpkg" ]; then                              
    /usr/sbin/installer -pkg "$installdir/pkgs/$tclpkg" -target "/"       
  fi                                                                                  
fi 

exit $?
