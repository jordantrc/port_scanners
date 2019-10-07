#!/bin/bash

usage () { 
	echo "Usage: masscan.sh [-p <top n ports>] -r <scan rate> -t <targets> -o <output file basename>"
	echo "	-t:		target specification can be either a file, a network with subnet mask, or a"
	echo "			single IP address" 
}


while getopts "hp:r:t:o:" OPTION; do
	case "$OPTION" in
		h ) usage; exit;;
		p ) NUM_PORTS="$OPTARG";;
		r ) RATE="$OPTARG";;
		t ) TARGETS="$OPTARG";;
		o ) OUTPUTBASE="$OPTARG";;
		\?) echo "Unknown option: -$OPTARG" >&2; exit 1;;
		: ) echo "Missing argument for -$OPTARG" >&2; exit 1;;
		* ) echo "Invalid option provided: -$OPTARG" >&2; exit 1;;
	esac
done

# test required arguments
if [ ! "$RATE" ] || [ ! "$TARGETS" ] || [ ! "$OUTPUTBASE" ]
then
	echo "Missing required arguments"
	usage
	exit 1
fi

# set the target list - either a network and subnet mask or file
if [ -f "$TARGETS" ]; 
then
	TARGET_SPECIFICATION="-iL $TARGETS"
	TARGET_LIST=`cat $TARGETS`
elif [[ "$TARGETS" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || [[ "$TARGETS" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
then
	TARGET_SPECIFICATION="$TARGETS"
	TARGET_LIST="$TARGETS"
fi

# set the port list for scanning
DEFAULT_PORTLIST="1,3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110,111,113,119,135,139,143-144,179,199,254,255,280,311,389,\
427,443-445,464,465,497,513-515,543,544,548,554,587,593,625,631,636,646,787,808,873,902,993,995,999,1000,1022,\
1024-1033,1035-1041,1044,1048-1050,1053,1054,1056,1058,1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,\
1720,1723,1755,1761,1801,1900,1935,1993,1998,2000-2002,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,\
2869,2967,3000,3001,3128,3268,3306,3389,3689,3690,3703,3986,4000,4001,4045,4899,5000,5001,5003,5009,5050,5051,5060,\
5101,5120,5190,5357,5432,5555,5556,5631,5666,5800,5900,5901,5985,6000-6002,6004,6112,6646,7000-7002,7070,7937,7938,8000-8002,\
8008-8010,8031,8080,8081,8443,8888,9000,9001,9090,9100,9102,9999,10000,10010,32768,32771,49152-49157,50000"
TOP_100_PORTLIST=( 80 23 443 21 22 25 3389 110 445 139 143 53 135 3306 8080 1723 111 995 993 5900 1025 587 8888 199 \
	1720 465 548 113 81 6001 10000 514 5060 179 1026 2000 8443 8000 32768 554 26 1433 49152 2001 515 8008 49154 \
	1027 5666 646 5000 5631 631 49153 8081 2049 88 79 5800 106 2121 1110 49155 6000 513 990 5357 427 49156 543 \
	544 5101 144 7 389 8009 3128 444 9999 5009 7070 5190 3000 5432 1900 3986 13 1029 9 5051 6646 49157 1028 873 \
	1755 2717 4899 9100 119 37 )

if [ ! "$NUM_PORTS" ]
then
	PORTLIST=$DEFAULT_PORTLIST
else
	if [ "$NUM_PORTS" -ge 1 -a "$NUM_PORTS" -le 100 ]
	then
		# construct the port list
		PORTLIST=""
		i=0
		for port in ${TOP_100_PORTLIST[@]:0:$NUM_PORTS}; do
			PORTLIST+="$port"
			i=$((i+1))
			if [[ "$i" -lt $NUM_PORTS ]]
			then
				PORTLIST+=","
			fi
		done
	else
		echo "Number of ports must be between 1 and 100"
		exit 1
	fi
fi

echo "PORTLIST = $PORTLIST"

MASSCAN_CMD="masscan $TARGET_SPECIFICATION --ping -p$PORTLIST --rate $RATE -oG $OUTPUTBASE.gmasscan -oL $OUTPUTBASE.masscan"

LOGFILE=$OUTPUTBASE"_log.txt"
echo "============ifconfig===============" > $LOGFILE
ifconfig >> $LOGFILE
echo "============/etc/resolv.conf===============" >> $LOGFILE
cat /etc/resolv.conf >> $LOGFILE
echo "============netstat -rn===============" >> $LOGFILE
netstat -rn >> $LOGFILE
echo "============date===============" >> $LOGFILE
date >> $LOGFILE
echo "============masscan command===============" >> $LOGFILE
echo "$MASSCAN_CMD" >> $LOGFILE
echo "============targets===============" >> $LOGFILE
echo "$TARGET_LIST" >> $LOGFILE
echo "============masscan output===============" >> $LOGFILE

TIMESTAMP=`date`
echo "STARTING MASSCAN - $TIMESTAMP" >> $LOGFILE
$MASSCAN_CMD | tee -a $LOGFILE

TIMESTAMP=`date`
echo "MASSCAN FINISHED - $TIMESTAMP" >> $LOGFILE
