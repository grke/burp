#
# Regular cron jobs for the burp package
#
# Run the burp client every 20 minutes with the 'timed' option. The burp server
# will decide whether it is yet time to do a backup or not.
# It might be a good idea to change the numbers below for different clients,
# in order to spread the load a bit.
#7,27,47 * * * *	root	[ -x /usr/sbin/burp ] && /usr/sbin/burp -a t >>/var/log/burp-client 2>&1
