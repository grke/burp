#!/usr/bin/env bash

PROGRAM="burp_tool"
PROGRAM_VERSION=0.2.0
PROGRAM_BUILD=2017122601
AUTHOR="(C) 2017 by Orsiris de Jong"
CONTACT="http://www.netpower.fr - ozy@netpower.fr"
IS_STABLE=yes

## burp_tool.sh - A script to check burp backup sanity
## burp is written by Graham Keeling, see http://burp.grke.org

## burp_tool.sh can verify a given number of backups for each client. It can run verifiy operations in parallel.
## Verify operations are timed in order to stop them after a given amount of time, leaving the system performance ready for backup operations.
## The script can also list clients that have outdated backups. It uses two different methods to list clients in order to detect rogue clients.
## It can also ensure that the burp server service is running properly, relaunch it if needed, on a scheduled basis.
## The script can send a warning / error when problems are found, even while operating.
## burp_tool.sh can also launch vss_strip for each file found in a given directory.

## Set an unique identifier for the script
INSTANCE_ID="base"

## Alert mail subject
MAIL_ALERT_MSG="Execution of $PROGRAM instance $INSTANCE_ID on $(date) has warnings/errors."

## Backup verifications are timed in seconds.
## After how much seconds a warning should be logged (defaults to 3 hours)
SOFT_MAX_EXEC_TIME=10800
## After how much seconds a verification process should be stopped (defaults to 10 hours)
HARD_MAX_EXEC_TIME=36000

## Burp executable (can be set to /usr/bin/burp, /usr/local/bin/burp...)
BURP_EXECUTABLE=burp

## Burp service type (can be "initv" or "systemd")
SERVICE_TYPE=systemd

## How many simultaneous verify operations should be launched (please check I/O and CPU usage before increasing this)
PARELLEL_VERIFY_CONCURRENCY=2

# ------------ Do not modify under this line unless you have great cow powers --------------

if ! type "$BASH" > /dev/null; then
	echo "Please run this script only with bash shell. Tested on bash >= 3.2"
	exit 127
fi

export LC_ALL=C

_LOGGER_SILENT=false
_LOGGER_VERBOSE=false
_LOGGER_ERR_ONLY=false
_LOGGER_PREFIX="date"
if [ "$KEEP_LOGGING" == "" ]; then
	KEEP_LOGGING=721
fi

# Initial error status, logging 'WARN', 'ERROR' or 'CRITICAL' will enable alerts flags
ERROR_ALERT=false
WARN_ALERT=false

LOCAL_USER=$(whoami)
LOCAL_HOST=$(hostname)

SCRIPT_PID=$$

TSTAMP=$(date '+%Y%m%dT%H%M%S.%N')

ALERT_LOG_FILE="$RUN_DIR/$PROGRAM.$SCRIPT_PID.$TSTAMP.last.log"

## Default log file until config file is loaded
if [ -w /var/log ]; then
	LOG_FILE="/var/log/$PROGRAM.log"
elif ([ "$HOME" != "" ] && [ -w "$HOME" ]); then
	LOG_FILE="$HOME/$PROGRAM.log"
elif [ -w . ]; then
	LOG_FILE="./$PROGRAM.log"
else
	LOG_FILE="/tmp/$PROGRAM.log"
fi

## Default directory where to store temporary run files
if [ -w /tmp ]; then
	RUN_DIR=/tmp
elif [ -w /var/tmp ]; then
	RUN_DIR=/var/tmp
else
	RUN_DIR=.
fi

#### Logger SUBSET ####

# Array to string converter, see http://stackoverflow.com/questions/1527049/bash-join-elements-of-an-array
# usage: joinString separaratorChar Array
function joinString {
	local IFS="$1"; shift; echo "$*";
}

# Sub function of Logger
function _Logger {
	local logValue="${1}"           # Log to file
	local stdValue="${2}"           # Log to screeen
	local toStdErr="${3:-false}"    # Log to stderr instead of stdout

	if [ "$logValue" != "" ]; then
		echo -e "$logValue" >> "$LOG_FILE"
		# Current log file
		echo -e "$logValue" >> "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}.$SCRIPT_PID.$TSTAMP"
	fi

	if [ "$stdValue" != "" ] && [ "$_LOGGER_SILENT" != true ]; then
		if [ $toStdErr == true ]; then
			# Force stderr color in subshell
			(>&2 echo -e "$stdValue")

		else
			echo -e "$stdValue"
		fi
	fi
}

# Remote logger similar to below Logger, without log to file and alert flags
function RemoteLogger {
	local value="${1}"              # Sentence to log (in double quotes)
	local level="${2}"              # Log level
	local retval="${3:-undef}"      # optional return value of command

	if [ "$_LOGGER_PREFIX" == "time" ]; then
		prefix="TIME: $SECONDS - "
	elif [ "$_LOGGER_PREFIX" == "date" ]; then
		prefix="R $(date) - "
	else
		prefix=""
	fi

	if [ "$level" == "CRITICAL" ]; then
		_Logger "" "$prefix\e[1;33;41m$value\e[0m" true
		if [ $_DEBUG == "yes" ]; then
			_Logger -e "" "[$retval] in [$(joinString , ${FUNCNAME[@]})] SP=$SCRIPT_PID P=$$" true
		fi
		return
	elif [ "$level" == "ERROR" ]; then
		_Logger "" "$prefix\e[91m$value\e[0m" true
		if [ $_DEBUG == "yes" ]; then
			_Logger -e "" "[$retval] in [$(joinString , ${FUNCNAME[@]})] SP=$SCRIPT_PID P=$$" true
		fi
		return
	elif [ "$level" == "WARN" ]; then
		_Logger "" "$prefix\e[33m$value\e[0m" true
		if [ $_DEBUG == "yes" ]; then
			_Logger -e "" "[$retval] in [$(joinString , ${FUNCNAME[@]})] SP=$SCRIPT_PID P=$$" true
		fi
		return
	elif [ "$level" == "NOTICE" ]; then
		if [ $_LOGGER_ERR_ONLY != true ]; then
			_Logger "" "$prefix$value"
		fi
		return
	elif [ "$level" == "VERBOSE" ]; then
		if [ $_LOGGER_VERBOSE == true ]; then
			_Logger "" "$prefix$value"
		fi
		return
	elif [ "$level" == "ALWAYS" ]; then
		_Logger  "" "$prefix$value"
		return
	elif [ "$level" == "DEBUG" ]; then
		if [ "$_DEBUG" == "yes" ]; then
			_Logger "" "$prefix$value"
			return
		fi
	else
		_Logger "" "\e[41mLogger function called without proper loglevel [$level].\e[0m" true
		_Logger "" "Value was: $prefix$value" true
	fi
}

# General log function with log levels:

# Environment variables
# _LOGGER_SILENT: Disables any output to stdout & stderr
# _LOGGER_ERR_ONLY: Disables any output to stdout except for ALWAYS loglevel
# _LOGGER_VERBOSE: Allows VERBOSE loglevel messages to be sent to stdout

# Loglevels
# Except for VERBOSE, all loglevels are ALWAYS sent to log file

# CRITICAL, ERROR, WARN sent to stderr, color depending on level, level also logged
# NOTICE sent to stdout
# VERBOSE sent to stdout if _LOGGER_VERBOSE = true
# ALWAYS is sent to stdout unless _LOGGER_SILENT = true
# DEBUG & PARANOIA_DEBUG are only sent to stdout if _DEBUG=yes
function Logger {
	local value="${1}"              # Sentence to log (in double quotes)
	local level="${2}"              # Log level
	local retval="${3:-undef}"      # optional return value of command

	if [ "$_LOGGER_PREFIX" == "time" ]; then
		prefix="TIME: $SECONDS - "
	elif [ "$_LOGGER_PREFIX" == "date" ]; then
		prefix="$(date) - "
	else
		prefix=""
	fi

	## Obfuscate _REMOTE_TOKEN in logs (for ssh_filter usage only in osync and obackup)
	value="${value/env _REMOTE_TOKEN=$_REMOTE_TOKEN/__(o_O)__}"
	value="${value/env _REMOTE_TOKEN=\$_REMOTE_TOKEN/__(o_O)__}"

	if [ "$level" == "CRITICAL" ]; then
		_Logger "$prefix($level):$value" "$prefix\e[1;33;41m$value\e[0m" true
		ERROR_ALERT=true
		# ERROR_ALERT / WARN_ALERT isn't set in main when Logger is called from a subprocess. Need to keep this flag.
		echo -e "[$retval] in [$(joinString , ${FUNCNAME[@]})] SP=$SCRIPT_PID P=$$\n$prefix($level):$value" >> "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}.error.$SCRIPT_PID.$TSTAMP"
		return
	elif [ "$level" == "ERROR" ]; then
		_Logger "$prefix($level):$value" "$prefix\e[91m$value\e[0m" true
		ERROR_ALERT=true
		echo -e "[$retval] in [$(joinString , ${FUNCNAME[@]})] SP=$SCRIPT_PID P=$$\n$prefix($level):$value" >> "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}.error.$SCRIPT_PID.$TSTAMP"
		return
	elif [ "$level" == "WARN" ]; then
		_Logger "$prefix($level):$value" "$prefix\e[33m$value\e[0m" true
		WARN_ALERT=true
		echo -e "[$retval] in [$(joinString , ${FUNCNAME[@]})] SP=$SCRIPT_PID P=$$\n$prefix($level):$value" >> "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}.warn.$SCRIPT_PID.$TSTAMP"
		return
	elif [ "$level" == "NOTICE" ]; then
		if [ "$_LOGGER_ERR_ONLY" != true ]; then
			_Logger "$prefix$value" "$prefix$value"
		fi
		return
	elif [ "$level" == "VERBOSE" ]; then
		if [ $_LOGGER_VERBOSE == true ]; then
			_Logger "$prefix($level):$value" "$prefix$value"
		fi
		return
	elif [ "$level" == "ALWAYS" ]; then
		_Logger "$prefix$value" "$prefix$value"
		return
	elif [ "$level" == "DEBUG" ]; then
		if [ "$_DEBUG" == "yes" ]; then
			_Logger "$prefix$value" "$prefix$value"
			return
		fi
	else
		_Logger "\e[41mLogger function called without proper loglevel [$level].\e[0m" "\e[41mLogger function called without proper loglevel [$level].\e[0m" true
		_Logger "Value was: $prefix$value" "Value was: $prefix$value" true
	fi
}
#### Logger SUBSET END ####

# Portable child (and grandchild) kill function tester under Linux, BSD and MacOS X
function KillChilds {
	local pid="${1}" # Parent pid to kill childs
	local self="${2:-false}" # Should parent be killed too ?

	# Paranoid checks, we can safely assume that $pid shouldn't be 0 nor 1
	if [ $(IsInteger "$pid") -eq 0 ] || [ "$pid" == "" ] || [ "$pid" == "0" ] || [ "$pid" == "1" ]; then
		Logger "Bogus pid given [$pid]." "CRITICAL"
		return 1
	fi

	if kill -0 "$pid" > /dev/null 2>&1; then
		# Warning: pgrep is not native on cygwin, have this checked in CheckEnvironment
		if children="$(pgrep -P "$pid")"; then
			if [[ "$pid" == *"$children"* ]]; then
				Logger "Bogus pgrep implementation." "CRITICAL"
				children="${children/$pid/}"
			fi
			for child in $children; do
				KillChilds "$child" true
			done
		fi
	fi

	# Try to kill nicely, if not, wait 15 seconds to let Trap actions happen before killing
	if [ "$self" == true ]; then
		# We need to check for pid again because it may have disappeared after recursive function call
		if kill -0 "$pid" > /dev/null 2>&1; then
			kill -s TERM "$pid"
			Logger "Sent SIGTERM to process [$pid]." "DEBUG"
			if [ $? != 0 ]; then
				sleep 15
				Logger "Sending SIGTERM to process [$pid] failed." "DEBUG"
				kill -9 "$pid"
				if [ $? != 0 ]; then
					Logger "Sending SIGKILL to process [$pid] failed." "DEBUG"
					return 1
				fi      # Simplify the return 0 logic here
			else
				return 0
			fi
		else
			return 0
		fi
	else
		return 0
	fi
}

function KillAllChilds {
	local pids="${1}" # List of parent pids to kill separated by semi-colon
	local self="${2:-false}" # Should parent be killed too ?


	local errorcount=0

	IFS=';' read -a pidsArray <<< "$pids"
	for pid in "${pidsArray[@]}"; do
		KillChilds $pid $self
		if [ $? != 0 ]; then
			errorcount=$((errorcount+1))
			fi
	done
	return $errorcount
}

function TrapQuit {
	local exitcode
	# Get ERROR / WARN alert flags from subprocesses that call Logger
	if [ -f "$RUN_DIR/$PROGRAM.Logger.warn.$SCRIPT_PID.$TSTAMP" ]; then
		WARN_ALERT=true
	fi
	if [ -f "$RUN_DIR/$PROGRAM.Logger.error.$SCRIPT_PID.$TSTAMP" ]; then
		ERROR_ALERT=true
	fi
	if [ $ERROR_ALERT == true ]; then
		Logger "$PROGRAM finished with errors." "ERROR"
		if [ "$_DEBUG" != "yes" ]
		then
			SendAlert
		else
			Logger "Debug mode, no alert mail will be sent." "NOTICE"
		fi
		exitcode=1
	elif [ $WARN_ALERT == true ]; then
		Logger "$PROGRAM finished with warnings." "WARN"
		if [ "$_DEBUG" != "yes" ]
		then
			SendAlert
		else
			Logger "Debug mode, no alert mail will be sent." "NOTICE"
		fi
		exitcode=2      # Warning exit code must not force daemon mode to quit
	else
		Logger "$PROGRAM finished." "ALWAYS"
		SendAlert
		exitcode=0
	fi
	CleanUp
	KillChilds $SCRIPT_PID > /dev/null 2>&1
	exit $exitcode
}

# osync/obackup/pmocr script specific mail alert function, use SendEmail function for generic mail sending
function SendAlert {
	local runAlert="${1:-false}" # Specifies if current message is sent while running or at the end of a run

	#__CheckArguments 0-1 $# "$@"    #__WITH_PARANOIA_DEBUG

	local attachment
	local attachmentFile
	local subject
	local body

	if [ "$DESTINATION_MAILS" == "" ]; then
		return 0
	fi

	if [ "$_DEBUG" == "yes" ]; then
		Logger "Debug mode, no warning mail will be sent." "NOTICE"
		return 0
	fi

	eval "cat \"$LOG_FILE\" $COMPRESSION_PROGRAM > $ALERT_LOG_FILE"
	if [ $? != 0 ]; then
		Logger "Cannot create [$ALERT_LOG_FILE]" "WARN"
		attachment=false
	else
		attachment=true
	fi
	if [ -e "$RUN_DIR/$PROGRAM._Logger.$SCRIPT_PID.$TSTAMP" ]; then
		if [ "$MAIL_BODY_CHARSET" != "" ] && type iconv > /dev/null 2>&1; then
			iconv -f UTF-8 -t $MAIL_BODY_CHARSET "$RUN_DIR/$PROGRAM._Logger.$SCRIPT_PID.$TSTAMP" > "$RUN_DIR/$PROGRAM._Logger.iconv.$SCRIPT_PID.$TSTAMP"
			body="$MAIL_ALERT_MSG"$'\n\n'"$(cat $RUN_DIR/$PROGRAM._Logger.iconv.$SCRIPT_PID.$TSTAMP)"
		else
			body="$MAIL_ALERT_MSG"$'\n\n'"$(cat $RUN_DIR/$PROGRAM._Logger.$SCRIPT_PID.$TSTAMP)"
		fi
	fi

	if [ $ERROR_ALERT == true ]; then
		subject="Error alert from $PROGRAM $INSTANCE_ID"
	elif [ $WARN_ALERT == true ]; then
		subject="Warning alert from $PROGRAM $INSTANCE_ID"
	else
		subject="Message from $PROGRAM $INSTANCE_ID"
	fi

	if [ $runAlert == true ]; then
		subject="Currently runing - $subject"
	else
		subject="Finished run - $subject"
	fi

	if [ "$attachment" == true ]; then
		attachmentFile="$ALERT_LOG_FILE"
	fi

	SendEmail "$subject" "$body" "$DESTINATION_MAILS" "$attachmentFile" "$SENDER_MAIL" "$SMTP_SERVER" "$SMTP_PORT" "$SMTP_ENCRYPTION" "$SMTP_USER" "$SMTP_PASSWORD"

	# Delete tmp log file
	if [ "$attachment" == true ]; then
		if [ -f "$ALERT_LOG_FILE" ]; then
			rm -f "$ALERT_LOG_FILE"
		fi
	fi
}


# Generic email sending function.
# Usage (linux / BSD), attachment is optional, can be "/path/to/my.file" or ""
# SendEmail "subject" "Body text" "receiver@example.com receiver2@otherdomain.com" "/path/to/attachment.file"
# Usage (Windows, make sure you have mailsend.exe in executable path, see http://github.com/muquit/mailsend)
# attachment is optional but must be in windows format like "c:\\some\path\\my.file", or ""
# smtp_server.domain.tld is mandatory, as is smtpPort (should be 25, 465 or 587)
# encryption can be set to tls, ssl or none
# smtpUser and smtpPassword are optional
# SendEmail "subject" "Body text" "receiver@example.com receiver2@otherdomain.com" "/path/to/attachment.file" "senderMail@example.com" "smtpServer.domain.tld" "smtpPort" "encryption" "smtpUser" "smtpPassword"
function SendEmail {
	local subject="${1}"
	local message="${2}"
	local destinationMails="${3}"
	local attachment="${4}"
	local senderMail="${5}"
	local smtpServer="${6}"
	local smtpPort="${7}"
	local encryption="${8}"
	local smtpUser="${9}"
	local smtpPassword="${10}"


	local mail_no_attachment=
	local attachment_command=

	local encryption_string=
	local auth_string=

	if [ ! -f "$attachment" ]; then
		attachment_command="-a $attachment"
		mail_no_attachment=1
	else
		mail_no_attachment=0
	fi

	if [ "$LOCAL_OS" == "Busybox" ] || [ "$LOCAL_OS" == "Android" ]; then
		if [ "$smtpPort" == "" ]; then
			Logger "Missing smtp port, assuming 25." "WARN"
			smtpPort=25
		fi
		if type sendmail > /dev/null 2>&1; then
			if [ "$encryption" == "tls" ]; then
				echo -e "Subject:$subject\r\n$message" | $(type -p sendmail) -f "$senderMail" -H "exec openssl s_client -quiet -tls1_2 -starttls smtp -connect $smtpServer:$smtpPort" -au"$smtpUser" -ap"$smtpPassword" "$destinationMails"
			elif [ "$encryption" == "ssl" ]; then
				echo -e "Subject:$subject\r\n$message" | $(type -p sendmail) -f "$senderMail" -H "exec openssl s_client -quiet -connect $smtpServer:$smtpPort" -au"$smtpUser" -ap"$smtpPassword" "$destinationMails"
			else
				echo -e "Subject:$subject\r\n$message" | $(type -p sendmail) -f "$senderMail" -S "$smtpServer:$smtpPort" -au"$smtpUser" -ap"$smtpPassword" "$destinationMails"
			fi

			if [ $? != 0 ]; then
				Logger "Cannot send alert mail via $(type -p sendmail) !!!" "WARN"
				# Don't bother try other mail systems with busybox
				return 1
			else
				return 0
			fi
		else
			Logger "Sendmail not present. Won't send any mail" "WARN"
			return 1
		fi
	fi

	if type mutt > /dev/null 2>&1 ; then
		# We need to replace spaces with comma in order for mutt to be able to process multiple destinations
		echo "$message" | $(type -p mutt) -x -s "$subject" "${destinationMails// /,}" $attachment_command
		if [ $? != 0 ]; then
			Logger "Cannot send mail via $(type -p mutt) !!!" "WARN"
		else
			Logger "Sent mail using mutt." "NOTICE"
			return 0
		fi
	fi

	if type mail > /dev/null 2>&1 ; then
		# We need to detect which version of mail is installed
		if ! $(type -p mail) -V > /dev/null 2>&1; then
			# This may be MacOS mail program
			attachment_command=""
		elif [ "$mail_no_attachment" -eq 0 ] && $(type -p mail) -V | grep "GNU" > /dev/null; then
			attachment_command="-A $attachment"
		elif [ "$mail_no_attachment" -eq 0 ] && $(type -p mail) -V > /dev/null; then
			attachment_command="-a$attachment"
		else
			attachment_command=""
		fi

		echo "$message" | $(type -p mail) $attachment_command -s "$subject" "$destinationMails"
		if [ $? != 0 ]; then
			Logger "Cannot send mail via $(type -p mail) with attachments !!!" "WARN"
			echo "$message" | $(type -p mail) -s "$subject" "$destinationMails"
			if [ $? != 0 ]; then
				Logger "Cannot send mail via $(type -p mail) without attachments !!!" "WARN"
			else
				Logger "Sent mail using mail command without attachment." "NOTICE"
				return 0
			fi
		else
			Logger "Sent mail using mail command." "NOTICE"
			return 0
		fi
	fi

	if type sendmail > /dev/null 2>&1 ; then
		echo -e "Subject:$subject\r\n$message" | $(type -p sendmail) "$destinationMails"
		if [ $? != 0 ]; then
			Logger "Cannot send mail via $(type -p sendmail) !!!" "WARN"
		else
			Logger "Sent mail using sendmail command without attachment." "NOTICE"
			return 0
		fi
	fi

	# Windows specific
	if type "mailsend.exe" > /dev/null 2>&1 ; then
		if [ "$senderMail" == "" ]; then
			Logger "Missing sender email." "ERROR"
			return 1
		fi
		if [ "$smtpServer" == "" ]; then
			Logger "Missing smtp port." "ERROR"
			return 1
		fi
		if [ "$smtpPort" == "" ]; then
			Logger "Missing smtp port, assuming 25." "WARN"
			smtpPort=25
		fi
		if [ "$encryption" != "tls" ] && [ "$encryption" != "ssl" ]  && [ "$encryption" != "none" ]; then
			Logger "Bogus smtp encryption, assuming none." "WARN"
			encryption_string=
		elif [ "$encryption" == "tls" ]; then
			encryption_string=-starttls
		elif [ "$encryption" == "ssl" ]:; then
			encryption_string=-ssl
		fi
		if [ "$smtpUser" != "" ] && [ "$smtpPassword" != "" ]; then
			auth_string="-auth -user \"$smtpUser\" -pass \"$smtpPassword\""
		fi
		$(type mailsend.exe) -f "$senderMail" -t "$destinationMails" -sub "$subject" -M "$message" -attach "$attachment" -smtp "$smtpServer" -port "$smtpPort" $encryption_string $auth_string
		if [ $? != 0 ]; then
			Logger "Cannot send mail via $(type mailsend.exe) !!!" "WARN"
		else
			Logger "Sent mail using mailsend.exe command with attachment." "NOTICE"
			return 0
		fi
	fi

	# pfSense specific
	if [ -f /usr/local/bin/mail.php ]; then
		echo "$message" | /usr/local/bin/mail.php -s="$subject"
		if [ $? != 0 ]; then
			Logger "Cannot send mail via /usr/local/bin/mail.php (pfsense) !!!" "WARN"
		else
			Logger "Sent mail using pfSense mail.php." "NOTICE"
			return 0
		fi
	fi

	# If function has not returned 0 yet, assume it is critical that no alert can be sent
	Logger "Cannot send mail (neither mutt, mail, sendmail, sendemail, mailsend (windows) or pfSense mail.php could be used)." "ERROR" # Is not marked critical because execution must continue
}

function TrapError {
	local job="$0"
	local line="$1"
	local code="${2:-1}"

	if [ $_LOGGER_SILENT == false ]; then
		(>&2 echo -e "\e[45m/!\ ERROR in ${job}: Near line ${line}, exit code ${code}\e[0m")
	fi
}

function IsInteger {
	local value="${1}"
	if [[ $value =~ ^[0-9]+$ ]]; then
		echo 1
	else
		echo 0
	fi
}

_OFUNCTIONS_SPINNER="|/-\\"
function Spinner {
	if [ $_LOGGER_SILENT == true ] || [ "$_LOGGER_ERR_ONLY" == true ]; then
		return 0
	else
		printf " [%c]  \b\b\b\b\b\b" "$_OFUNCTIONS_SPINNER"
		#printf "\b\b\b\b\b\b"
		_OFUNCTIONS_SPINNER=${_OFUNCTIONS_SPINNER#?}${_OFUNCTIONS_SPINNER%%???}
		return 0
	fi
}

# Time control function for background processes, suitable for multiple synchronous processes
# Fills a global variable called WAIT_FOR_TASK_COMPLETION_$callerName that contains list of failed pids in format pid1:result1;pid2:result2
# Also sets a global variable called HARD_MAX_EXEC_TIME_REACHED_$callerName to true if hardMaxTime is reached

# Standard wait $! emulation would be WaitForTaskCompletion $! 0 0 1 0 true false true false

function WaitForTaskCompletion {
	local pids="${1}" # pids to wait for, separated by semi-colon
	local softMaxTime="${2:-0}"     # If process(es) with pid(s) $pids take longer than $softMaxTime seconds, will log a warning, unless $softMaxTime equals 0.
	local hardMaxTime="${3:-0}"     # If process(es) with pid(s) $pids take longer than $hardMaxTime seconds, will stop execution, unless $hardMaxTime equals 0.
	local sleepTime="${4:-.05}"     # Seconds between each state check, the shorter this value, the snappier it will be, but as a tradeoff cpu power will be used (general values between .05 and 1).
	local keepLogging="${5:-0}"     # Every keepLogging seconds, an alive log message is send. Setting this value to zero disables any alive logging.
	local counting="${6:-true}"     # Count time since function has been launched (true), or since script has been launched (false)
	local spinner="${7:-true}"      # Show spinner (true), don't show anything (false)
	local noErrorLog="${8:-false}"  # Log errors when reaching soft / hard max time (false), don't log errors on those triggers (true)

	local callerName="${FUNCNAME[1]}"

	local log_ttime=0 # local time instance for comparaison

	local seconds_begin=$SECONDS # Seconds since the beginning of the script
	local exec_time=0 # Seconds since the beginning of this function

	local retval=0 # return value of monitored pid process
	local errorcount=0 # Number of pids that finished with errors

	local pid       # Current pid working on
	local pidCount # number of given pids
	local pidState # State of the process

	local pidsArray # Array of currently running pids
	local newPidsArray # New array of currently running pids


	if [ $counting == true ]; then  # If counting == false _SOFT_ALERT should be a global value so no more than one soft alert is shown
		local _SOFT_ALERT=false # Does a soft alert need to be triggered, if yes, send an alert once
	fi

	IFS=';' read -a pidsArray <<< "$pids"
	pidCount=${#pidsArray[@]}

	# Set global var default
	eval "WAIT_FOR_TASK_COMPLETION_$callerName=\"\""
	eval "HARD_MAX_EXEC_TIME_REACHED_$callerName=false"

	while [ ${#pidsArray[@]} -gt 0 ]; do
		newPidsArray=()

		if [ $spinner == true ]; then
			Spinner
		fi
		if [ $counting == true ]; then
			exec_time=$((SECONDS - seconds_begin))
		else
			exec_time=$SECONDS
		fi

		if [ $keepLogging -ne 0 ]; then
			if [ $((($exec_time + 1) % $keepLogging)) -eq 0 ]; then
				if [ $log_ttime -ne $exec_time ]; then # Fix when sleep time lower than 1s
					log_ttime=$exec_time
					Logger "Current tasks still running with pids [$(joinString , ${pidsArray[@]})]." "NOTICE"
				fi
			fi
		fi

		if [ $exec_time -gt $softMaxTime ]; then
			if [ "$_SOFT_ALERT" != true ] && [ $softMaxTime -ne 0 ] && [ $noErrorLog != true ]; then
				Logger "Max soft execution time exceeded for task [$callerName] with pids [$(joinString , ${pidsArray[@]})]." "WARN"
				_SOFT_ALERT=true
				SendAlert true
			fi
		fi

		if [ $exec_time -gt $hardMaxTime ] && [ $hardMaxTime -ne 0 ]; then
			if [ $noErrorLog != true ]; then
				Logger "Max hard execution time exceeded for task [$callerName] with pids [$(joinString , ${pidsArray[@]})]. Stopping task execution." "ERROR"
			fi
			for pid in "${pidsArray[@]}"; do
				KillChilds $pid true
				if [ $? == 0 ]; then
					Logger "Task with pid [$pid] stopped successfully." "NOTICE"
				else
					Logger "Could not stop task with pid [$pid]." "ERROR"
				fi
				errorcount=$((errorcount+1))
			done
			if [ $noErrorLog != true ]; then
				SendAlert true
			fi
			eval "HARD_MAX_EXEC_TIME_REACHED_$callerName=true"
			return $errorcount
		fi

		for pid in "${pidsArray[@]}"; do
			if [ $(IsInteger $pid) -eq 1 ]; then
				if kill -0 $pid > /dev/null 2>&1; then
					# Handle uninterruptible sleep state or zombies by ommiting them from running process array (How to kill that is already dead ? :)
					pidState="$(eval $PROCESS_STATE_CMD)"
					if [ "$pidState" != "D" ] && [ "$pidState" != "Z" ]; then
						newPidsArray+=($pid)
					fi
				else
					# pid is dead, get it's exit code from wait command
					wait $pid
					retval=$?
					if [ $retval -ne 0 ]; then
						Logger "${FUNCNAME[0]} called by [$callerName] finished monitoring [$pid] with exitcode [$retval]." "DEBUG"
						errorcount=$((errorcount+1))
						# Welcome to variable variable bash hell
						if [ "$(eval echo \"\$WAIT_FOR_TASK_COMPLETION_$callerName\")" == "" ]; then
							eval "WAIT_FOR_TASK_COMPLETION_$callerName=\"$pid:$retval\""
						else
							eval "WAIT_FOR_TASK_COMPLETION_$callerName=\";$pid:$retval\""
						fi
					fi
				fi
			fi
		done


		pidsArray=("${newPidsArray[@]}")
		# Trivial wait time for bash to not eat up all CPU
		sleep $sleepTime


	done


	# Return exit code if only one process was monitored, else return number of errors
	# As we cannot return multiple values, a global variable WAIT_FOR_TASK_COMPLETION contains all pids with their return value
	if [ $pidCount -eq 1 ]; then
		return $retval
	else
		return $errorcount
	fi
}

# Take a list of commands to run, runs them sequentially with numberOfProcesses commands simultaneously runs
# Returns the number of non zero exit codes from commands
# Use cmd1;cmd2;cmd3 syntax for small sets, use file for large command sets
# Only 2 first arguments are mandatory
# Sets a global variable called HARD_MAX_EXEC_TIME_REACHED to true if hardMaxTime is reached
# ParallelExec numberOfProcesses commandsArg readFromFile softMaxTime hardMaxTime sleepTime keepLogging counting spinner noErrorLog

function ParallelExec {
	local numberOfProcesses="${1}"          # Number of simultaneous commands to run
	local commandsArg="${2}"                # Semi-colon separated list of commands, or path to file containing one command per line
	local readFromFile="${3:-false}"        # commandsArg is a file (true), or a string (false)
	local softMaxTime="${4:-0}"             # If process(es) with pid(s) $pids take longer than $softMaxTime seconds, will log a warning, unless $softMaxTime equals 0.
	local hardMaxTime="${5:-0}"             # If process(es) with pid(s) $pids take longer than $hardMaxTime seconds, will stop execution, unless $hardMaxTime equals 0.
	local sleepTime="${6:-.05}"             # Seconds between each state check, the shorter this value, the snappier it will be, but as a tradeoff cpu power will be used (general values between .05 and 1).
	local keepLogging="${7:-0}"             # Every keepLogging seconds, an alive log message is send. Setting this value to zero disables any alive logging.
	local counting="${8:-true}"             # Count time since function has been launched (true), or since script has been launched (false)
	local spinner="${9:-false}"             # Show spinner (true), don't show spinner (false)
	local noErrorLog="${10:-false}"         # Log errors when reaching soft / hard max time (false), don't log errors on those triggers (true)

	local callerName="${FUNCNAME[1]}"
	#__CheckArguments 2-10 $# "$@"                           #__WITH_PARANOIA_DEBUG

	local log_ttime=0 # local time instance for comparaison

	local seconds_begin=$SECONDS # Seconds since the beginning of the script
	local exec_time=0 # Seconds since the beginning of this function

	local commandCount
	local command
	local pid
	local counter=0
	local commandsArray
	local pidsArray
	local newPidsArray
	local retval
	local errorCount=0
	local pidState
	local commandsArrayPid

	local hasPids=false # Are any valable pids given to function ?          #__WITH_PARANOIA_DEBUG

	# Set global var default
	eval "HARD_MAX_EXEC_TIME_REACHED_$callerName=false"

	if [ $counting == true ]; then  # If counting == false _SOFT_ALERT should be a global value so no more than one soft alert is shown
		local _SOFT_ALERT=false # Does a soft alert need to be triggered, if yes, send an alert once
	fi

	if [ $readFromFile == true ];then
		if [ -f "$commandsArg" ]; then
			commandCount=$(wc -l < "$commandsArg")
		else
			commandCount=0
		fi
	else
		IFS=';' read -r -a commandsArray <<< "$commandsArg"
		commandCount=${#commandsArray[@]}
	fi

	Logger "Runnning $commandCount commands in $numberOfProcesses simultaneous processes." "DEBUG"

	while [ $counter -lt "$commandCount" ] || [ ${#pidsArray[@]} -gt 0 ]; do

		if [ $spinner == true ]; then
			Spinner
		fi

		if [ $counting == true ]; then
			exec_time=$((SECONDS - seconds_begin))
		else
			exec_time=$SECONDS
		fi

		if [ $keepLogging -ne 0 ]; then
			if [ $((($exec_time + 1) % $keepLogging)) -eq 0 ]; then
				if [ $log_ttime -ne $exec_time ]; then # Fix when sleep time lower than 1s
					log_ttime=$exec_time
					Logger "There are $((commandCount-counter)) / $commandCount tasks in the queue. Currently, ${#pidsArray[@]} tasks running with pids [$(joinString , ${pidsArray[@]})]." "NOTICE"
				fi
			fi
		fi

		if [ $exec_time -gt $softMaxTime ]; then
			if [ "$_SOFT_ALERT" != true ] && [ $softMaxTime -ne 0 ] && [ $noErrorLog != true ]; then
				Logger "Max soft execution time exceeded for task [$callerName] with pids [$(joinString , ${pidsArray[@]})]." "WARN"
				_SOFT_ALERT=true
				SendAlert true
			fi
		fi
		if [ $exec_time -gt $hardMaxTime ] && [ $hardMaxTime -ne 0 ]; then
			if [ $noErrorLog != true ]; then
				Logger "Max hard execution time exceeded for task [$callerName] with pids [$(joinString , ${pidsArray[@]})]. Stopping task execution." "ERROR"
			fi
			for pid in "${pidsArray[@]}"; do
				KillChilds $pid true
				if [ $? == 0 ]; then
					Logger "Task with pid [$pid] stopped successfully." "NOTICE"
				else
					Logger "Could not stop task with pid [$pid]." "ERROR"
				fi
			done
			if [ $noErrorLog != true ]; then
				SendAlert true
			fi
			eval "HARD_MAX_EXEC_TIME_REACHED_$callerName=true"
			# Return the number of commands that haven't run / finished run
			return $((commandCount - counter + ${#pidsArray[@]}))
		fi

		while [ $counter -lt "$commandCount" ] && [ ${#pidsArray[@]} -lt $numberOfProcesses ]; do
			if [ $readFromFile == true ]; then
				command=$(awk 'NR == num_line {print; exit}' num_line=$((counter+1)) "$commandsArg")
			else
				command="${commandsArray[$counter]}"
			fi
			Logger "Running command [$command]." "DEBUG"
			eval "$command" >> "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}.$callerName.$SCRIPT_PID.$TSTAMP" 2>&1 &
			pid=$!
			pidsArray+=($pid)
			commandsArrayPid[$pid]="$command"
			counter=$((counter+1))
		done


		newPidsArray=()
		for pid in "${pidsArray[@]}"; do
			if [ $(IsInteger $pid) -eq 1 ]; then
				# Handle uninterruptible sleep state or zombies by ommiting them from running process array (How to kill that is already dead ? :)
				if kill -0 $pid > /dev/null 2>&1; then
					pidState="$(eval $PROCESS_STATE_CMD)"
					if [ "$pidState" != "D" ] && [ "$pidState" != "Z" ]; then
						newPidsArray+=($pid)
					fi
				else
					# pid is dead, get it's exit code from wait command
					wait $pid
					retval=$?
					if [ $retval -ne 0 ]; then
						Logger "Command [${commandsArrayPid[$pid]}] failed with exit code [$retval]." "ERROR"
						errorCount=$((errorCount+1))
					fi
				fi
				hasPids=true                                    ##__WITH_PARANOIA_DEBUG
			fi
		done

		if [ $hasPids == false ]; then                                  ##__WITH_PARANOIA_DEBUG
			Logger "No valable pids given." "ERROR"                 ##__WITH_PARANOIA_DEBUG
		fi                                                              ##__WITH_PARANOIA_DEBUG
		pidsArray=("${newPidsArray[@]}")

		# Trivial wait time for bash to not eat up all CPU
		sleep $sleepTime

		if [ "$_PERF_PROFILER" == "yes" ]; then                         ##__WITH_PARANOIA_DEBUG
			_PerfProfiler                                           ##__WITH_PARANOIA_DEBUG
		fi                                                              ##__WITH_PARANOIA_DEBUG
	done

	return $errorCount
}


function CleanUp {

	if [ "$_DEBUG" != "yes" ]; then
		rm -f "$RUN_DIR/$PROGRAM."*".$SCRIPT_PID.$TSTAMP"
		# Fix for sed -i requiring backup extension for BSD & Mac (see all sed -i statements)
		rm -f "$RUN_DIR/$PROGRAM."*".$SCRIPT_PID.$TSTAMP.tmp"
	fi
}

# Takes as many file arguments as needed
function InterleaveFiles {

	local counter=0
	local hasLine=true

	while [ $hasLine == true ]; do
		hasLine=false
		for i in "$@"; do
			line=$(awk 'NR == num_line {print; exit}' num_line=$((counter+1)) "$i")
			if [ -n "$line" ]; then
				echo "$line"
			hasLine=true
			fi
		done
		counter=$((counter+1))
	done
}

function ListClients {
	local backupDir="${1}"
	local configFile="${2}"

	local clientIsIncluded
	local clientIsExcluded
	local excludeArray

	local client
	local configString

	if [ -f "$configFile" ]; then
		configString="-c \"$configFile\""
	fi

	# File 'backup_stats' is there only when a backup is finished
	find "$backupDir" -mindepth 3 -maxdepth 3 -type f -name "backup_stats" | grep -e '.*' > /dev/null
	if [ $? != 0 ]; then
		Logger "The directory [$backupDir] does not seem to be a burp folder. Please check the path. Additionnaly, protocol 2 directores need to specify the dedup group directory and the client subfolder." "ERROR"
	fi

	# Using both burp -a S list and find method in order to find maximum backup clients
	cmd="$BURP_EXECUTABLE $configString -a S | grep \"last backup\" | awk '{print \$1}' > \"$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-1.$SCRIPT_PID.$TSTAMP\""
	Logger "Running cmd [$cmd]." "DEBUG"
	eval "$cmd" &
	WaitForTaskCompletion $! 1800 3600 1 $KEEP_LOGGING true true false
	if [ $? != 0 ]; then
		Logger "Enumerating burp clients via [$BURP_EXECUTABLE $configString -a S] failed." "ERROR"
	else
		Logger "Burp method found the following clients:\n$(cat $RUN_DIR/$PROGRAM.${FUNCNAME[0]}-1.$SCRIPT_PID.$TSTAMP)" "DEBUG"
	fi

	#TODO: sed expressions are GNU and won't probably work on BSD nor Mac
	# First exp removes everything before last '/'
	find "$backupDir" -mindepth 1 -maxdepth 1 -type d | sed -e "s/\(.*\)\/\(.*\)/\2/g" > "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-2.$SCRIPT_PID.$TSTAMP"

	while IFS=$'\n' read -r client; do
		find "$backupDir$client" -mindepth 2 -maxdepth 2 -type f -name "backup_stats" | grep -e '.*' > /dev/null
		if [ $? == 0 ]; then
			echo "$client" >> "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-3.$SCRIPT_PID.$TSTAMP"
		fi
	done < "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-2.$SCRIPT_PID.$TSTAMP"

	if [ ! -f "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-3.$SCRIPT_PID.$TSTAMP" ]; then
		touch "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-3.$SCRIPT_PID.$TSTAMP"
	fi

	Logger "Detection method found the following clients:\n$(cat $RUN_DIR/$PROGRAM.${FUNCNAME[0]}-3.$SCRIPT_PID.$TSTAMP)" "DEBUG"

	# Merge all clients found by burp executable and manual check
	sort "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-1.$SCRIPT_PID.$TSTAMP" "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-3.$SCRIPT_PID.$TSTAMP" | uniq > "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-4.$SCRIPT_PID.$TSTAMP"

	while IFS=$'\n' read -r client; do
		clientIsIncluded=false
		clientIsExcluded=false

		IFS=',' read -a includeArray <<< "$INCLUDE_CLIENTS"
		for i in "${includeArray[@]}"; do
			echo "$client" | grep -e "^"$i"$" > /dev/null 2>&1
			if [ $? == 0 ]; then
				clientIsIncluded=true
			fi
		done

		IFS=',' read -a excludeArray <<< "$EXCLUDE_CLIENTS"
		for i in "${excludeArray[@]}"; do
			echo "$client" | grep -e "^"$i"$" > /dev/null 2>&1
			if [ $? == 0 ]; then
				clientIsExcluded=true
			fi
		done

		if ([ $clientIsIncluded == false ] && [ $clientIsExcluded == true ]); then
			Logger "Ommiting client [$client]." "NOTICE"
		else
			if [ -f "$backupDir$client/current/timestamp" ]; then
				Logger "Found client [$client]." "NOTICE"
				CLIENT_LIST+=("$client")
			else
				Logger "Client [$client] does not have any backups." "WARN"
			fi
		fi

	done < "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-4.$SCRIPT_PID.$TSTAMP"
}

function IsClientIdle {
	local client="${1}"
	local configFile="${2}"

	local exitCode
	local configString

        if [ -f "$configFile" ]; then
                configString="-c \"$configFile\""
        fi

	Logger "Checking if client [$client] is currently idle." "DEBUG"

	cmd="$BURP_EXECUTABLE $configString -a S -C $client | grep \"Status: idle\""
	WaitForTaskCompletion $! 120 300 1 $KEEP_LOGGING true true false
	exitCode=$?

	if [ $exitCode -ne 0 ]; then
		Logger "Client [$client] is currently backing up." "NOTICE"
		return $exitCode
	else
		return $exitCode
	fi
}

function VerifyBackups {
	local backupDir="${1}"
	local numberToVerify="${2}"
	local restoreClient="${3}"
	local configFile="${4}"

	local backupNumber
	local exitCode
	local client

	local configString
	local interleaveFileArgs=()

	# Parallel execution needs to check different clients, so lists should be written in form for each number: for each client create command

	#TODO: ParallelExec should be able to get soft and hard exec times per thread and not only per whole execution
	#TODO: ParallelExec can't check a condition in order to launch a specific task.
	#      Implement a secondary condition list, if condition is not met, don't execute, or postpone after others
	Logger "Running backup verification" "NOTICE"

	if [ -f "$configFile" ]; then
		configString="-c \"$configFile\""
	fi

	for client in "${CLIENT_LIST[@]}"; do
		# Only backups containing file backup_stats are valid
		find "$backupDir$client" -mindepth 2 -maxdepth 2 -type f -name "backup_stats" | sort -nr | head -n $numberToVerify | sed -e 's/.*\([0-9]\{7\}\).*/\1/' > "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-1.$SCRIPT_PID.$TSTAMP"
		Logger "Can check $(cat $RUN_DIR/$PROGRAM.${FUNCNAME[0]}-1.$SCRIPT_PID.$TSTAMP | wc -l) backups for [$client]." "NOTICE"
		while IFS=$'\n' read -r backupNumber; do
			#TODO: sed expressions won't probably work on BSD nor Mac
			# sed here removes all lines containing only block logs (64 chars + number)
			Logger "Preparing verification of backup [$backupNumber] for client [$client]." "NOTICE"
			echo "$BURP_EXECUTABLE $configString -C $client -a v -b $backupNumber | sed '/^[BbfFvud]\{64\} [0-9]\+$/d' >> \"$LOG_FILE\" 2>&1" >> "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-2.$client.$SCRIPT_PID.$TSTAMP"
		done < "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-1.$SCRIPT_PID.$TSTAMP"

		if [ -f "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-2.$client.$SCRIPT_PID.$TSTAMP" ]; then
			interleaveFileArgs+=("$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-2.$client.$SCRIPT_PID.$TSTAMP")
		fi
	done

	InterleaveFiles "${interleaveFileArgs[@]}" > "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-3.$SCRIPT_PID.$TSTAMP"

	Logger "Executing parallel commands\n$(cat $RUN_DIR/$PROGRAM.${FUNCNAME[0]}-3.$SCRIPT_PID.$TSTAMP)" "DEBUG"
	ParallelExec $PARELLEL_VERIFY_CONCURRENCY "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}-3.$SCRIPT_PID.$TSTAMP" true $SOFT_MAX_EXEC_TIME $HARD_MAX_EXEC_TIME 1 $KEEP_LOGGING true true false
	exitCode=$?
	if [ $exitCode -ne 0 ]; then
	Logger "Client backup verification produced errors [$exitCode]." "ERROR"
	else
		Logger "Client backup verification succeed." "NOTICE"
	fi

	Logger "Backup verification done." "NOTICE"
}

function ListOutdatedClients {
	local backupDir="${1}"
	local oldDays="${2}"

	local found=false

	Logger "Checking for outdated clients." "NOTICE"

	for client in "${CLIENT_LIST[@]}"; do
		recentBackups=$(find "$backupDir$client" -maxdepth 2 -name "backup_stats"  -and ! -path "*working*" -ctime -$oldDays | wc -l)
		if [ $recentBackups -le 0 ]; then
			Logger "Client [$client] has no backups newer than [$oldDays] days." "ERROR"
			found=true
		fi
	done

	if [ $found == false ]; then
		Logger "No outdated clients found." "NOTICE"
	else
		Logger "Outdated client checks done." "NOTICE"
	fi
}

function UnstripVSS {
	local path="${1}"
	local exitCode=0

	if ! type vss_strip > /dev/null 2>&1; then
		Logger "Could not find vss_strip binary. Please check your path variable." "CRITICAL"
		exit 1
	fi

	find "$path" -type f -print0 | while IFS= read -r -d $'\0' file; do
		Logger "Unstripping file [$file]." "NOTICE"
		mv -f "$file" "$file.old"
		if [ $? -ne 0 ]; then
			Logger "Could not move [$file] to [$file.old] for processing." "WARN"
			exitCode=2
			continue
		else
			vss_strip -i "$file.old" -o "$file"
			if [ $? -ne 0 ]; then
				Logger "Could not vss_strip [$file.old] to [$file]." "WARN"
				exitCode=2
				mv -f "$file.old" "$file"
				if [ $? -ne 0 ]; then
					Logger "Coult not move back [$file.old] to [$file]." "WARN"
				fi
			else
				rm -f "$file.old"
				if [ $? -ne 0 ]; then
					Logger "Could not delete temporary file [$file.old]." "WARN"
					exitCode=2
				continue
				fi
			fi
		fi
	done

	return $exitCode
}

function VerifyService {
	local serviceName="${1}"
	local serviceType="${2}"

	local serviceNameArray
	local serviceStatusCommand
	local serviceStartCommand

	IFS=',' read -a serviceNameArray <<< "$serviceName"
	for i in "${serviceNameArray[@]}"; do
		if [ "$serviceType" == "initv" ]; then
			serviceStatusCommand="service $i status"
			serviceStartCommand="service $i start"
		elif [ "$serviceType" == "systemd" ]; then
			serviceStatusCommand="systemctl status $i"
			serviceStartCommand="systemctl start $i"
		else
			serviceStatusCommand="service $i status"
			serviceStartCommand="systemctl start $i"
			Logger "No valid service type given [$serviceType]. Trying default initV style." "ERROR"
		fi

		eval "$serviceStatusCommand" > /dev/null 2>&1 &
		WaitForTaskCompletion $! 120 300 1 $KEEP_LOGGING true true false
		if [ $? -ne 0 ]; then
			Logger "Service [$i] is not started. Trying to start it." "WARN"
			eval "$serviceStartCommand" > /dev/null 2>&1 &
			WaitForTaskCompletion $! 120 300 1 $KEEP_LOGGING true true false
			if [ $? -ne 0 ]; then
				Logger "Cannot start service [$i]." "CRITICAL"
				SendAlert
			else
				Logger "Service [$i] was successfuly started." "WARN"
				SendAlert
			fi
		else
			Logger "Service [$i] is running." "NOTICE"
		fi
	done
}

function Init {
	# Set error exit code if a piped command fails
	set -o pipefail
	set -o errtrace

	trap TrapQuit TERM EXIT HUP QUIT
}

function Usage {

	if [ "$IS_STABLE" != "yes" ]; then
		echo -e "\e[93mThis is an unstable dev build. Please use with caution.\e[0m"
	fi
	echo "$PROGRAM $PROGRAM_VERSION $PROGRAM_BUILD"
	echo "$AUTHOR"
	echo "$CONTACT"
	echo ""
	echo "Usage:"
	echo "$0 [OPTIONS]"
	echo ""
	echo "[OPTIONS]"
	echo "-d, --backup-dir=\"\"                The directory where the client backup directories are"
	echo "-o, --check-outdated-clients=n     Check for clients that don't have backups newer than n days"
	echo "-v, --verify-last-backups=n        Verify the last n backups of all clients"
	echo "-i, --include-clients=\"\"           Comma separated list of clients to include. This list takes grep -e compatible regular expressions, includes prevail excludes"
	echo "-e, --exclude-clients=\"\"           Comma separated list of clients to exclude. This list takes grep -e compatible regular expressions"
	echo "-c, --config-file=\"\"               Path to optional burp client configuration file (defaults to /etc/burp/burp.conf)"
	echo "-s, --vss-strip-path=\"\"            Run vss_strip for all files in given path"
	echo "-j, --verify-service=\"\"            Comma separated list of burp services to check and restart if they aren't running"
	echo ""
	echo "Examples:"
	echo "$0 -d /path/to/burp/protocol1 -v 3 -c /etc/burp/burp.conf"
	echo "$0 -d /path/to/burp/protocol2/global/clients --check-outdated-clients7 --exclude-clients=restoreclient,burp-ui.local"
	echo "$0 --vss-strip-path=/path/to/restored/files"
	echo "$0 -j burp.service" 
	echo "Exclude via regex all clients beginning with 'cli' and otherclient1/2:"
	echo "$0 --backup-dir=/path/to/burp/protocol1 --exclude-clients=cli.*,otherclient1,otherclient2"
	echo ""
	echo "Additionnal options"
	echo "--no-maxtime                       Don't stop checks after the configured maximal time in script"
	echo "-s, --silent                       Don't output to stdout, log file only"
	echo "--errors-only                      Don't output anything but errors."
	echo ""
	echo "--destination-mails=\"\"             Space separated list of email adresses where to send warning and error mails"
	echo "--instance-id=\"\"                   Arbitrary identifier for log files and alert mails"
	exit 128
}


#### SCRIPT ENTRY POINT
DESTINATION_MAILS=""
no_maxtime=false
ERROR_ALERT=false
WARN_ALERT=false
CONFIG_FILE=""
BACKUP_DIR=""
VERIFY_BACKUPS=""
INCLUDE_CLIENTS=""
EXCLUDE_CLIENTS=""
OUTDATED_DAYS=""
CLIENT_LIST=()
VSS_STRIP_DIR=""
VERIFY_SERVICE=""

function GetCommandlineArguments {
	local isFirstArgument=true
	if [ $# -eq 0 ]
	then
		Usage
	fi
	while [ $# -gt 0 ]; do
		## Options name is $1, argument is $2 unless there is a separator other than space
		case $1 in
			--instance-id=*)
			INSTANCE_ID="${1##*=}"
			;;
			--silent)
			_LOGGER_SILENT=true
			;;
			--verbose)
			_LOGGER_VERBOSE=true
			;;
			--no-maxtime)
			no_maxtime=true
			;;
			--help|-h|--version)
			Usage
			;;
			--backup-dir=*)
			BACKUP_DIR="${1##*=}"
			;;
			-d)
			BACKUP_DIR="${2}"
			shift
			;;
			--check-outdated-clients=*)
			OUTDATED_DAYS="${1##*=}"
			;;
			-o)
			OUTDATED_DAYS="${2}"
			shift
			;;
			--verify-last-backups=*)
			VERIFY_BACKUPS="${1##*=}"
			;;
			-v)
			VERIFY_BACKUPS="${2}"
			shift
			;;
			--include-clients=*)
			INCLUDE_CLIENTS="${1##*=}"
			;;
			-i)
			INCLUDE_CLIENTS="${2}"
			shift
			;;
			--exclude-clients=*)
			EXCLUDE_CLIENTS="${1##*=}"
			;;
			-e)
			EXCLUDE_CLIENTS="${2}"
			shift
			;;
			--config-file=*)
			CONFIG_FILE="${1##*=}"
			;;
			-c)
			CONFIG_FILE="${2}"
			shift
			;;
			--vss-strip-path=*)
			VSS_STRIP_DIR="${1##*=}"
			;;
			-s)
			VSS_STRIP_DIR="${2}"
			shift
			;;
			-j)
			VERIFY_SERVICE="${2}"
			shift
			;;
			--verify-service=*)
			VERIFY_SERVICE="${1##*=}"
			;;
			--errors-only)
			_LOGGER_ERR_ONLY=true
			;;
			--destination-mails=*)
			DESTINATION_MAILS="${1##*=}"
			;;
			--no-maxtime)
			SOFT_MAX_EXEC_TIME=0
			HARD_MAX_EXEC_TIME=0
			;;
			*)
			if [ $isFirstArgument == false ]; then
				Logger "Unknown option '${1}'" "CRITICAL"
				Usage
			fi
			;;
		esac
		shift
		isFirstArgument=false
	done
}

GetCommandlineArguments "$@"
Init

if [ "$LOGFILE" == "" ]; then
	if [ -w /var/log ]; then
		LOG_FILE="/var/log/$PROGRAM.$INSTANCE_ID.log"
	elif ([ "$HOME" != "" ] && [ -w "$HOME" ]); then
		LOG_FILE="$HOME/$PROGRAM.$INSTANCE_ID.log"
	else
		LOG_FILE="./$PROGRAM.$INSTANCE_ID.log"
	fi
else
	LOG_FILE="$LOGFILE"
fi
if [ ! -w "$(dirname $LOG_FILE)" ]; then
	echo "Cannot write to log [$(dirname $LOG_FILE)]."
else
	Logger "Script begin, logging to [$LOG_FILE]." "DEBUG"
fi

DATE=$(date)
Logger "-------------------------------------------------------------" "NOTICE"
Logger "$DATE - $PROGRAM $PROGRAM_VERSION script begin." "ALWAYS"
Logger "-------------------------------------------------------------" "NOTICE"

if [ "$VSS_STRIP_DIR" != "" ]; then
	if [ -d "$VSS_STRIP_DIR" ]; then
		UnstripVSS "$VSS_STRIP_DIR"
		exit $?
	else
		Logger "Bogus path given to unstrip [$VSS_STRIP_DIR]." "CRITICAL"
		exit 1
	fi
fi

if [ "$VERIFY_SERVICE" != "" ]; then
	VerifyService "$VERIFY_SERVICE" "$SERVICE_TYPE"
fi

if [ "$BACKUP_DIR" != "" ]; then
	if [ ! -d "$BACKUP_DIR" ]; then
		Logger "Backup dir [$BACKUP_DIR] doesn't exist." "CRITICAL"
		exit 1
	else
		# Make sure there is only one trailing slash on path
		BACKUP_DIR="${BACKUP_DIR%/}/"
	fi

	if [ "$CONFIG_FILE" != "" ]; then
		if [ ! -f "$CONFIG_FILE" ]; then
			Logger "Bogus configuration file [$CONFIG_FILE] given." "CRITICAL"
			exit 1
		fi
	fi

	ListClients "$BACKUP_DIR" "$CONFIG_FILE"

	if [ "$VERIFY_BACKUPS" != "" ]; then
		if [ $(IsInteger "$VERIFY_BACKUPS") -ne 0 ]; then
			VerifyBackups "$BACKUP_DIR" $VERIFY_BACKUPS "$RESTORE_CLIENT" "$CONFIG_FILE"
		else
			Logger "Bogus --verify-last-backups value [$VERIFY_BACKUPS]." "CRITICAL"
			exit 1
		fi
	fi

	if [ "$OUTDATED_DAYS" != "" ]; then
		if [ $(IsInteger "$OUTDATED_DAYS") -ne 0 ]; then
			ListOutdatedClients "$BACKUP_DIR" $OUTDATED_DAYS
		else
			Logger "Bogus --check-outdated-clients value [$OUTDATED_DAYS]." "CRITICAL"
			exit 1
		fi
	fi
fi
