The script should work as-is for CLI-based fuzzing.  Just drop in your own S3 
Access Key ID and Secret Access Key to sync results to S3.

To do GUI-base fuzzing, set GRAPHICAL=1 and change the package name variables 
to the GUI package you want to fuzz.  After you launch an instance, open an SSH
tunnel with something like:

ssh -i BFF.pem -l ubuntu -L 5900:localhost:5900 \
   <INSTANCE HOSTNAME OR IP ADDRESS> 'x11vnc -localhost -display :0'
   
Then VNC to localhost:5900 to connect.