#!/bin/bash
# By Shaun Blackburn
# Spring 2013

#======= Variables to configure the fuzzing campaign =======

CONFIGURL=""								# URL to download bff.cfg.  Leave blank use the included one and set fuzzing values below

PACKAGETOFUZZ="imagemagick"					# as it appears in apt-get repo
EXECUTABLE="convert"				# full path preferable
PROCNAME="convert"							# name of the process when running. likely the same as the executable

S3ACCESSKEYID=""		# Enter your S3 Access Key ID
S3SECRETACCESSKEY=""	# Enter your S3 Secret Access Key
S3BUCKETPREFIX="fuzzresults"						# Name of the S3 bucket to use.  Will append the name of the package being fuzzed
S3LOGLOCATION="/var/log/s3.log"				# Location to log S3 errors on the fuzzing server(s)

GRAPHICAL=0									#If set to 1, will install a graphical environment and VNC server for fuzzing graphical programs
RESOLUTION=1024x768x16						#Desired GUI resolution

#=======		End configuration variables			=======

S3BUCKET=$S3BUCKETPREFIX"_"$PACKAGETOFUZZ	# Variable to hold S3 bucket name

apt-get update && apt-get -u upgrade		# Update the system

# Install a graphical environment if selected
if [ $GRAPHICAL -ne 0 ]
then
	apt-get install -y lxde xvfb x11vnc
fi

# Install dependencies and the package that will be fuzzed
apt-get install -y python-numpy python-scipy python-memcache gdb subversion build-essential libtool libncurses5-dev unzip libcaca-dev libcaca0 watchdog s3cmd zzuf $PACKAGETOFUZZ

# Download and unzip BFF
wget -P /home/ubuntu/ "http://www.cert.org/download/bff/BFF-2.6.zip"
mkdir /home/ubuntu/bff
unzip /home/ubuntu/BFF-2.6.zip -d /home/ubuntu/bff/
chown -hR ubuntu.ubuntu /home/ubuntu/bff

# Disable kernel memory randomization
echo "kernel.randomize_va_space=0" >> /etc/sysctl.conf

# Place symbolic links needed by BFF
ln -s `which $EXECUTABLE` /home/ubuntu/fuzzme
ln -s /home/ubuntu/bff/scripts /home/ubuntu/bff
ln -s /home/ubuntu/bff/results /home/ubuntu/results

# Create an upstart script to begin the BFF campaign on (re)boot
if [ $GRAPHICAL -ne 0 ]						# If fuzzing a GUI app, set up a virtual X frame buffer and launch the app in it
then
	cat > /etc/init/bff.conf <<EOF
# bff
description     "BFF"
start on filesystem and net-device-up IFACE!=lo
expect fork
respawn
pre-start script
    /usr/bin/s3cmd --config=/etc/s3cfg mb s3://$S3BUCKET 2>>$S3LOGLOCATION	#Creates the S3 bucket
end script
exec su - ubuntu -c "/home/ubuntu/launchbffgui.sh"
EOF
	chown root.root /etc/init/bff.conf
	chmod 0644 /etc/init/bff.conf
	# Create script to start the virtual frame buffer on Display 0 then launch BFF, top, and a third available console within it
	cat > /home/ubuntu/launchbffgui.sh <<EOF
#! /bin/bash
Xvfb -screen 0 $RESOLUTION -ac &
DISPLAY=:0 startlxde &
DISPLAY=:0 lxterminal -t BFF -e /home/ubuntu/bff/batch.sh &
DISPLAY=:0 lxterminal -t TOP -e top &
DISPLAY=:0 lxterminal -t BASH &
EOF
	chown ubuntu.ubuntu /home/ubuntu/launchbffgui.sh
	chmod 0644 /home/ubuntu/launchbffgui.sh
	chmod a+x /home/ubuntu/launchbffgui.sh
else										# If fuzzing a CLI app, start fuzzing in a screen session
	cat > /etc/init/bff.conf <<EOF
# bff
description     "BFF"
start on filesystem and net-device-up IFACE!=lo
expect fork
respawn
pre-start script
    /usr/bin/s3cmd --config=/etc/s3cfg mb s3://$S3BUCKET 2>>$S3LOGLOCATION	#Creates the S3 bucket
end script
exec su - ubuntu -c "/usr/bin/screen -dmS bff /home/ubuntu/bff/batch.sh"	#Launch BFF in a screen session owned by user ubuntu, then detach
EOF
	chown root.root /etc/init/bff.conf
	chmod 0644 /etc/init/bff.conf
fi

# Modify the BFF config file to point to the desired executable
sed -i 's\^cmdline=~/convert\cmdline=~/fuzzme\' /home/ubuntu/bff/conf.d/bff.cfg
sed -i "s/^killprocname=convert/killprocname=$PROCNAME/" /home/ubuntu/bff/conf.d/bff.cfg

# Create an s3cfg file with the S3 keys
cat > /etc/s3cfg <<EOF
[default]
access_key = $S3ACCESSKEYID
bucket_location = US
cloudfront_host = cloudfront.amazonaws.com
cloudfront_resource = /2010-07-15/distribution
default_mime_type = binary/octet-stream
delete_removed = False
dry_run = False
encoding = UTF-8
encrypt = False
follow_symlinks = False
force = False
get_continue = False
gpg_command = /usr/bin/gpg
gpg_decrypt = %(gpg_command)s -d --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s
gpg_encrypt = %(gpg_command)s -c --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s
gpg_passphrase = 
guess_mime_type = True
host_base = s3.amazonaws.com
host_bucket = %(bucket)s.s3.amazonaws.com
human_readable_sizes = False
list_md5 = False
log_target_prefix = 
preserve_attrs = True
progress_meter = True
proxy_host = 
proxy_port = 0
recursive = Falseap
recv_chunk = 4096
reduced_redundancy = False
secret_key = $S3SECRETACCESSKEY
send_chunk = 4096
simpledb_host = sdb.amazonaws.com
skip_existing = False
socket_timeout = 10
urlencoding_mode = normal
use_https = False
verbosity = WARNING
EOF

# Set up syncing of results to S3
cd ~
cat > /usr/sbin/s3sync <<EOF
#!/bin/bash
# Make sure bucket exists
s3cmd --config=/etc/s3cfg ls | grep -o "\w*$S3BUCKET\w*" | grep -x $S3BUCKET > bucketlist
if [ ! -s bucketlist ]
then
	# Create the bucket
	/usr/bin/s3cmd --config=/etc/s3cfg mb s3://$S3BUCKET 2>>$S3LOGLOCATION
fi
#Perform sync
s3cmd --config=/etc/s3cfg sync /home/ubuntu/results/ s3://$S3BUCKET 2>>$S3LOGLOCATION
rm bucketlist
EOF
chmod +x /usr/sbin/s3sync
echo "*/5 * * * * /usr/sbin/s3sync" > mycron
crontab mycron
rm mycron

# Reboot to implement changes and start the BFF campaign
reboot