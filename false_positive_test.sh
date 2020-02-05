#!/usr/bin/env bash
#
# Usage: false_positive_test.sh <directory>
#
# Checks for false positives given a directory
# as output by the scan_host_list.py utility.

directory=$1

database_ports=("1433" "3306" "1521" "5432")
file_transer_ports=("21")
ms_ports=("88" "135" "139" "389" "445" "636")
remote_access_ports=("22" "3389" "5900" "5901")
secure_web_ports=("443" "4443" "8443")
web_ports=("80" "8080" "8000" "8888")
all_ports=( "${database_ports[@]}" "${file_transfer_ports[@]}" "${ms_ports[@]}" "${remote_access_ports[@]}" \
            "${secure_web_ports[@]}" "${web_ports[@]}" )

for port in "${all_ports[@]}"; do
    host_file=$directory"/tcp_"$port".txt"

    if [ -f "$host_file" ]; then
        echo "Performing service detection for port $port hosts"
        scan_file=$directory"/service_version_tcp_"$port".gnmap"
        nmap -p $port -sV -Pn -iL $host_file -oG $scan_file
    fi
done

verify_ftp_port() {
    ip_address=$1
    port=$2
    result=""
    nmap_result=$(nmap -Pn -sV -p$port $ip_address -oG - | grep 'open/')

    # if nmap_result is empty, port is no longer open
    # consider false positive
    if [ ${#nmap_result} -eq 0 ]; then
        result="false-positive tcp $port $ip_address closed/filtered"
    else
        # get the service header
        detected_service=$(echo "$nmap_result" | 
            awk '{ for(i=5; i<NF; i++) printf "%s",$i OFS; if(NF) printf "%s",$NF; printf ORS}' | 
            cut -d "/" -f 7)
        service_header=$(echo "$nmap_result" | 
            awk '{ for(i=5; i<NF; i++) printf "%s",$i OFS; if(NF) printf "%s",$NF; printf ORS}' | 
            cut -d "/" -f 7)
    fi

}

verify_web_port() {
    secure=$1
    ip_address=$2
    port=$3
    result=""
    nmap_result=$(nmap -Pn -sV -p$port $ip_address -oG - | grep 'open/')
    
    # if nmap_result is empty, port is no longer open
    # consider false positive
    if [ ${#nmap_result} -eq 0 ]; then
        result="false-positive tcp $port $ip_address closed/filtered"
    else
        # determine identified server
        service_header=$(echo "$nmap_result" | 
            awk '{ for(i=5; i<NF; i++) printf "%s",$i OFS; if(NF) printf "%s",$NF; printf ORS}' | 
            cut -d "/" -f 7)
        if [[ "$service_header" =~ ^http\??$ ]] || [[ "${#service_header}" -eq 0 ]]; then
            result="false-positive tcp $port $ip_address unrecognized service header/protocol error/MFA redirect"
        fi
    fi

    return $result
}
