#!/bin/bash
#
# Converts a directory with files containing
# lists of systems with a particular open port
# into a single file with URL formatting.
#
# Usage: web_server_url.sh <directory> <output file>
#

usage() {
	echo "Usage: web_server_url.sh <directory> <output file>"
}

if [ "$#" -ne 2 ]; then
    echo "Illegal number of parameters, exiting"
    usage
    exit(1)
fi

DIR=$1
OUTPUT_FILE=$2
WEB_PORTS=("80", "3000", "7000", "7001", "7002", "8000",\
 "8080", "8081", "8888", "9000")
SECURE_WEB_PORTS=("443", "8443")

# look for files in DIR that contain secure and non-secure
# web ports
for p in ${WEB_PORTS[@]}; do
	FILE="$DIR/tcp_$p.txt"
	if [[ -f "$FILE" ]]; then
		cat $FILE | xargs -I {} echo "http://{}:$p" >> $OUTPUT_FILE
	fi
done

for p in ${SECURE_WEB_PORTS[@]}; do
	FILE="$DIR/tcp_$p.txt"
	if [[ -f "$FILE" ]]; then
		cat $FILE | xargs -I {} echo "https://{}:$p" >> $OUTPUT_FILE
	fi
done

exit(0)
