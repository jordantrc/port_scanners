#!/usr/bin/env python

"""
Takes a scan file and creates a
list of hosts accessible for each unique port
in the results file. Supports nmap greppable
output and masscan list output.

Usage: scan_host_list.py <scan file> <output directory>
    If the output directory exists, it will not create it.
"""

import argparse
import os


def host_output(output_directory, proto, port, host):
    """Write a host to an output file."""
    output_file = os.path.join(output_directory, "%s_%s.txt" % (proto, port))

    # write the host to the output file
    with open(output_file, 'a') as host_fd:
        host_fd.write("%s\n" % host)


def parse_line(line, output_directory, file_type, debug):
    """Parse a scan file line."""
    if line[0] == "#":
        return None

    if file_type == "masscan":
        if debug:
            print(f"DEBUG masscan line = {line}")
        state, proto, port, host, ident = line.split()
        host_output(output_directory, proto, port, host)
    elif file_type == "nmap":
        if debug:
            print(f"DEBUG nmap line = {line}")
        # Ignore these lines:
        # Host: 10.1.1.1 ()   Status: Up
        if "Status:" not in line:
            # Host: 10.1.1.1 ()   Ports: 21/filtered/tcp//ftp///, 80/open/tcp//http///,
            # 53/open|filtered/udp//domain///, 137/open/udp//netbios-ns///  Ignored State: filtered (195)
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
                    port, state, proto, _, desc, _, _, _ = p.split('/')
                    if state == "open":
                        host_output(output_directory, proto, port, host)
                except ValueError:
                    continue


    return True


def main():
    """The main function."""
    debug = False

    parser = argparse.ArgumentParser(description='Creates a list of hosts per protocol/port from a scan file.')
    parser.add_argument('--debug', '-d', action='store_true', help="Enable debug output")
    parser.add_argument('scan_file', help='Scan file to parse.')
    parser.add_argument('output_directory', help='Directory to put output files into, must not exist.')
    args = parser.parse_args()

    scan_file = args.scan_file
    output_directory = args.output_directory

    # test arguments
    assert os.path.isfile(scan_file)
    assert not os.path.isdir(output_directory)
    if args.debug is not None:
        debug = args.debug

    # make the directory
    os.mkdir(output_directory, 0o755)

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
            parse_line(line, output_directory, file_type, debug)


if __name__ == "__main__":
    main()
