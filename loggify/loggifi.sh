#!/usr/bin/env bash

        ## Configuration

VERSION="00.01.01.04"
HISTORICALMIN="20"
SYSLOG_FILE="/var/log/syslog"
AUTHLOG_FILE="/var/log/auth.log"
KERNELLOG_FILE="/var/log/kern.log"
FAIL2BAN_FILE="/var/log/fail2ban.log"
OUTPUT_FILE="/tmp/loggifi.syslog.log"
DEFAULT_LOG="/tmp/loggifi.log"
LOGGIFI_SYSLOG_FILE="/tmp/loggifi.syslog.log"
DEF_FILE="/var/lib/loggifi/loggifi.def"
DEF_FILE_FOLDER="/var/lib/loggifi"
DEF_FILE_DOWNLOAD="https://raw.githubusercontent.com/clarsen-007/Loggifi/refs/heads/master/Loggifi.definition/loggifi.def"
LOG_FILE="/tmp/scan_log_error.log"
LOGGIFI_MESSAGE_FILE="/tmp/loggifi.message.file.txt"
VERBOSE=0

        ## Commands

RM=$( which rm )
AWK=$( which awk )
DATE=$( which date )
MKDIR=$( which mkdir )
CURL=$( which curl )

        ## Handle optional flag

if [[ "$1" == "-v" ]]
    then
        VERBOSE=1
fi

if [[ "$1" == "-u" ]]
    then
        if [[ ! -d "$DEF_FILE_FOLDER" ]]
            then
                $MKDIR -p $DEF_FILE_FOLDER
        fi

        $CURL $DEF_FILE_DOWNLOAD > $DEF_FILE
        echo "Definition file downloaded..."
        exit 0
fi

if [[ "$1" == "-h" ]]
    then
        echo " Script used to collect last N minutes... "
        echo "   -h will show this message. "
        echo "   -v will display verbose output. "
        exit 0
fi

        ## Logging function

LOG() {
    if [ $VERBOSE -eq 1 ]; then
        echo "[INFO] $1"
    fi
}

ERROR_EXIT() {
    echo "[ERROR] $1" | tee -a "$DEFAULT_LOG" >&2
    exit 1
}

        ## Verify Loggifi definition file exists

if [[ ! -f "$DEF_FILE" ]]
    then
        ERROR_EXIT "$DEF_FILE file not found... Please run definition update with the -u flag."
fi

        ## Verify syslog file exists

if [[ ! -f "$SYSLOG_FILE" ]]
    then
        ERROR_EXIT "Syslog file not found at $SYSLOG_FILE"
fi

if [[ -f "$OUTPUT_FILE" ]]
    then
        $RM $OUTPUT_FILE
fi

LOG "Writing output to $OUTPUT_FILE"
LOG "Errors will be logged to $ERROR_LOG"
LOG "Reading from $SYSLOG_FILE"

        ## Get time window

CURRENT_TIME=$($DATE +"%Y-%m-%dT%H:%M:%S.999999+02:00")
START_TIME=$($DATE -d "$HISTORICALMIN minutes ago" +"%Y-%m-%dT%H:%M:%S.000000+02:00")

LOG "Filtering logs between $START_TIME and $CURRENT_TIME"

        ## Process syslog and write to output

LIST=( "$SYSLOG_FILE" "$AUTHLOG_FILE" "$KERNELLOG_FILE" "$FAIL2BAN_FILE" )

for ITEM in "${LIST[@]}"
        do

$AWK -v start="$START_TIME" -v end="$CURRENT_TIME" '
    function PARSE_TIMESTAMP(TS) {
        gsub(/([+-][0-9]{2}):[0-9]{2}$/, "", TS);  # Remove timezone offset
        return TS
    }

    {
        match($0, /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}/, TS)
        if (TS[0] != "") {
            T = PARSE_TIMESTAMP(TS[0])
            if (T >= start && T <= end) {
                print $0
            }
        }
    }
' "$ITEM" | tee -a "$OUTPUT_FILE" > /dev/null

## "$ITEM" | tee -a "$OUTPUT_FILE" 2>>"$DEFAULT_LOG"

          done

LOG "Done."

        ## Look for issues using loggify.def file

# Script to scan a syslog file for known message patterns defined in a config file

# Clear or create the error log
> "$LOG_FILE"

# Check if required files exist
if [[ ! -f "$LOGGIFI_SYSLOG_FILE" ]]; then
    echo "ERROR: Syslog file not found: $LOGGIFI_SYSLOG_FILE" | tee -a "$LOG_FILE"
    exit 1
fi

if [[ ! -f "$DEF_FILE" ]]; then
    echo "ERROR: Definition file not found: $DEF_FILE" | tee -a "$LOG_FILE"
    exit 1
fi

# Extract MSG patterns from loggifi.def
# These are the strings we want to search for in the syslog
MSG_PATTERNS=()
while IFS= read -r line; do
    if [[ "$line" =~ MSG:\"(.*)\" ]]; then
        MSG="${BASH_REMATCH[1]}"
        MSG_PATTERNS+=("$MSG")
    fi
done < "$DEF_FILE"

# Check if any MSG patterns were extracted
if [ ${#MSG_PATTERNS[@]} -eq 0 ]; then
    echo "ERROR: No MSG patterns found in $DEF_FILE" | tee -a "$LOG_FILE"
    exit 1
fi

if [[ -f "$LOGGIFI_MESSAGE_FILE" ]]
    then
        $RM $LOGGIFI_MESSAGE_FILE
fi

sleep 5

# Now scan the syslog for each extracted pattern
echo "Scanning $LOGGIFI_SYSLOG_FILE for known messages..."
for pattern in "${MSG_PATTERNS[@]}"; do
    echo "Searching for: $pattern"
    grep -F "$pattern" "$LOGGIFI_SYSLOG_FILE" | tee -a "$LOGGIFI_MESSAGE_FILE" \
         || echo "No matches found for: $pattern" | tee -a "$LOG_FILE"
done

echo "Scan complete."

## Version info
## 00.01.01.04
## Changed definition file to download from Githib page
## 00.01.01.03
## Release
