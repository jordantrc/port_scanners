#!/usr/bin/env python3
#
# Takes a masscan report and
# grabs banners from open services
# using nmap. Then produces a report
# of services. The report is stored
# in CSV format and placed in the 
# output directory.
#
# Usage: 
# verify_and_report.py [OPTIONS] <scan file> <num concurrent scans> <max packets per second>
# OPTIONS:
#   -x, --exclude <comma separated list of ports>   exclude the list of ports from service detection
#   -v, --verbose                                   provide verbose output
#

import argparse
import csv
import ipaddress
import multiprocessing
import os
import subprocess
import sys


def host_output(output_directory, proto, port, host):
    """Write a host to an output file."""
    output_file = os.path.join(output_directory, "%s_%s.txt" % (proto, port))

    # write the host to the output file
    with open(output_file, 'a') as host_fd:
        host_fd.write("%s\n" % host)


def parse_scan_file(scan_file, output_directory, exclude_ports, verboseprint):
    """Parses the initial scan file."""
    with open(scan_file, 'r') as scan_fd:
        for i, line in enumerate(scan_fd):
            # read the header line to determine the file type
            if i == 0:
                if "#masscan" in line:
                    file_type = "masscan"
                elif "# Nmap" in line:
                    file_type = "nmap"
                else:
                    assert False, "file type unknown"
                verboseprint("[*] file type is %s" % file_type)
            port_info = parse_line(line, file_type, verboseprint)  # returns [[state, proto, port, host, banner],]
            for p in port_info:
                if p[0] == "open" and p[2] not in exclude_ports:
                    host_output(output_directory, p[1], p[2], p[3])


def produce_report(output_directory, report_file, verboseprint):
    """Generates the report."""
    verboseprint("[*] entering produce_report function")
    file_list = os.listdir(output_directory)
    service_detection_files = [os.path.join(output_directory, x) for x in file_list if "service_detection" in x]
    
    with open(report_file, 'w') as csv_fd:
        csvwriter = csv.writer(csv_fd, dialect='excel')
        csvwriter.writerow(['host', 'protocol', 'port', 'state', 'service_info'])
        for s in service_detection_files:
            with open(s, 'r') as s_fd:
                for line in s_fd.readlines():
                    port_info = parse_line(line, "nmap", verboseprint)
                    if len(port_info) > 0:
                        #print("line = %s, port_info = %s" % (line, port_info))
                        csvwriter.writerow([port_info[3], port_info[1], port_info[2], port_info[0], port_info[4]])


def parse_line(line, file_type, verboseprint):
    """Parse a scan file line, returns state, proto, port, host, banner."""
    result = []
    if line[0] == "#":
        return result

    if file_type == "masscan":
        state, proto, port, host, _ = line.split()
        result = ["open", proto, port, host, ""]
    elif file_type == "nmap":
        # Ignore these lines:
        # Host: 10.1.1.1 ()   Status: Up
        if "Status:" not in line:
            # Host: 10.1.1.1 ()   Ports: 21/filtered/tcp//ftp///, 80/open/tcp//http///,
            # 53/open|filtered/udp//domain///, 137/open/udp//netbios-ns///  Ignored State: filtered (195)
            # Ports: 25/open/tcp//smtp//Microsoft Exchange smtpd/
            host_info, port_info = line.split("Ports:")
            host = host_info.strip().split(' ')[1]

            # get the port information
            port_info = port_info.strip()
            if "Ignored State" in port_info:
                port_info, _ = port_info.split('Ignored State:')
            port_info = port_info.strip()
            port_list = port_info.split(',')
            port_list = [ x.strip() for x in port_list ]
            for p in port_list:
                try:
                    port, state, proto, _, _, _, banner, _ = p.split('/')
                    result.append([state, proto, port, host, banner])
                except ValueError as err:
                    print("[-] Error occurred: %s" % str(err))
                    print("[-] offending line: %s" % p)

    verboseprint("[*] parse line result: %s" % result)
    return result


def probe_service(args):
    """Probes all hosts given the host file, which has the naming convention <protocol>_<port>.txt"""
    pps = args[0]
    host_file = args[1]
    host_file_name = os.path.basename(host_file)
    host_file_dir = os.path.dirname(host_file)
    protocol, port = host_file_name.split(".")[0].split("_")
    #print("host_file_name = %s, protocol = %s, port = %s" % (host_file_name, protocol, port))

    if protocol in ["tcp", "udp"]:
        output_file = os.path.join(host_file_dir, "service_detection_%s_%s.gnmap" % (protocol, port))

        # determine the scan type and run it
        if protocol == "tcp":
            scan_type = ""  # nmap defaults to a TCP scan
        else:
            scan_type = "-sU"
        nmap_command = "nmap %s -Pn -p%s --max-rate %s -sV -iL %s -oG %s" % (scan_type, port, pps, host_file, output_file)
        print("[*] initiating service detection for %s/%s" % (protocol.upper(), port))
        print(nmap_command)
        nmap_command = nmap_command.split()
        result = subprocess.run(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if len(result.stderr) > 0:
            print("[-] ERROR in nmap command %s" % nmap_command)
            print("[-] %s" % result.stderr.decode('ascii'))


def main():
    verbose = False

    parser = argparse.ArgumentParser("verifies and reports on a masscan file")
    parser.add_argument("-x", "--exclude", required=False, help="ports to exclude, comma-sparated")
    parser.add_argument("-v", "--verbose", action="store_true", required=False, help="provide verbose output")
    parser.add_argument("scan_file", nargs=1, help="masscan file to use for verification and reporting")
    parser.add_argument("num_scans", nargs=1, help="number of scans to run concurrently")
    parser.add_argument("max_pps", nargs=1, help="maximum packets per second across all scans")
    args = parser.parse_args()

    # required arguments
    scan_file = args.scan_file[0]
    assert os.path.isfile(scan_file), "scan file %s does not exist" % scan_file
    # get directory of scan file
    scan_file_dir = os.path.dirname(scan_file)
    scan_file_base = os.path.splitext(os.path.basename(scan_file))[0]
    if scan_file_dir == "":
        scan_file_dir = "."
    output_directory = os.path.join(scan_file_dir, scan_file_base)
    report_output_file = os.path.join(output_directory, scan_file_base + ".csv")
    assert not os.path.isdir(output_directory), "output directory %s already exists" % output_directory
    
    num_scans = int(args.num_scans[0])
    max_pps = int(args.max_pps[0])
    pps_per_scan = max(1, int(max_pps / num_scans))

    # options
    exclude_ports = []
    if args.exclude is not None:
        exclude_ports = args.exclude.split(",")
        exclude_ports = [x.strip() for x in exclude_ports]
    if args.verbose is not None:
        verbose = args.verbose
        print("[*] enabling verbose output")
    verboseprint = print if verbose else lambda *a, **k: None

    # make the directory
    verboseprint("[*] creating directory")
    os.mkdir(output_directory, 0o755)

    parse_scan_file(scan_file, output_directory, exclude_ports, verboseprint)

    # output_directory is now full of files named protocol_port number.txt
    host_files = os.listdir(output_directory)
    host_files = [[pps_per_scan, os.path.join(output_directory, x)] for x in host_files]
    with multiprocessing.Pool(processes=num_scans) as pool:
        pool.map(probe_service, host_files)
    
    produce_report(output_directory, report_output_file, verboseprint)
    

if __name__ == "__main__":
    main()