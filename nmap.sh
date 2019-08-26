#!/bin/bash

if [ "$#" -ne 4 ]; then
	echo "Usage: nmap.sh <min rate - pps> <max rate - pps> <targets file> <output file basename>"
	exit 1
fi

MINRATE=$1
MAXRATE=$2
TARGETSFILE=$3
OUTPUTBASE=$4

NMAP_COMMAND="\
nmap -Pn -n -p 1,3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110,111,113,119,135,139,143-144,179,199,254,255,280,311,389,\
427,443-445,464,465,497,513-515,543,544,548,554,587,593,625,631,636,646,787,808,873,902,993,995,999,1000,1022,\
1024-1033,1035-1041,1044,1048-1050,1053,1054,1056,1058,1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,\
1720,1723,1755,1761,1801,1900,1935,1993,1998,2000-2002,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,\
2869,2967,3000,3001,3128,3268,3306,3389,3689,3690,3703,3986,4000,4001,4045,4899,5000,5001,5003,5009,5050,5051,5060,\
5101,5120,5190,5357,5432,5555,5631,5666,5800,5900,5901,5985,6000-6002,6004,6112,6646,7000,7070,7937,7938,8000,8002,\
8008-8010,8031,8080,8081,8443,8888,9000,9001,9090,9100,9102,9999,10000,10010,32768,32771,49152-49157,50000 \
-iL $TARGETSFILE \
-oA $OUTPUTBASE \
-v --traceroute -T4 --min-rate $MINRATE --max-rate $MAXRATE"

LOGFILE=$OUTPUTBASE"_log.txt"
TARGETS=`cat $TARGETSFILE`
echo "============ifconfig===============" > $LOGFILE
ifconfig >> $LOGFILE
echo "============/etc/resolv.conf===============" >> $LOGFILE
cat /etc/resolv.conf >> $LOGFILE
echo "============netstat -rn===============" >> $LOGFILE
netstat -rn >> $LOGFILE
echo "============date===============" >> $LOGFILE
date >> $LOGFILE
echo "============nmap command===============" >> $LOGFILE
echo $NMAP_COMMAND >> $LOGFILE
echo "============targets===============" >> $LOGFILE
echo $TARGETS >> $LOGFILE

echo "============Starting nmap command==============" >> $LOGFILE
date >> $LOGFILE
$NMAP_COMMAND | tee -a $LOGFILE
date >> $LOGFILE
echo "nmap finished" >> $LOGFILE
