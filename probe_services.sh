#!/usr/bin/env bash
#
# Usage: probe_services.sh <directory> <num jobs> <max packets per second>
#
# Checks for false positives given a directory
# as output by the scan_host_list.py utility.

if [ $# -ne 4 ]; then
    echo "Usage: probe_services.sh <directory> <num jobs> <max packets per second>"
    return 1
fi

directory=$1
num_jobs=$2
pps=$3

pps_per_job=expr $pps / $num_jobs
echo "[*] using $pps_per_job pps/job"

running_jobs=0
for f in ${directory}"/*"; do
    host_file=$directory"/"$f
    proto=$(echo $f | cut -d "_" -f 1)
    port=$(echo $f | cut -d "_" -f 2 | cut -d "." -f 1)    

    if [ ${proto} -ne "icmp" ]; then
        num_hosts=$(cat $host_file | sort | uniq | wc -l) 
        scan_file=$directory"/service_version_"$proto"_"$port".gnmap"
        if [${proto} -eq "udp" ]; then
            scan_type_option="-sU"
        else
            scan_type_option=""
        # run each nmap task as background job so it can be done in parallel
        nmap $scan_type_option --max-rate $pps_per_job -p $port -sV -Pn -iL $host_file -oG $scan_file &
        pid=$!
        running_jobs=$(expr $running_jobs + 1)
        echo "[*] started service detection job for $num_hosts $proto/$port hosts [PID $pid job $running_jobs of $num_jobs]"
        if [ $running_jobs -eq $num_jobs ]; then
            echo "[*] waiting for jobs to finish"
            wait
            echo "[*] all jobs completed"
            running_jobs=0
        fi
    fi
done

wait

echo "[*] all service detection jobs complete"
