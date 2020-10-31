#!/usr/bin/env python3
#
# Summarizes all the masscan reports in a directory.
# Given a directory, it will assume every csv file
# is a masscan report and process it.
#
# Usage: masscan_summary_report.py <directory> <output file>
#

import csv
import ipaddress
import os
import sys


def get_matching_index(data, target, open_tcp, open_udp):
    """returns the index in data that matches all three variables"""
    index = None
    for i, d in enumerate(data):
        if d['target'] == target and d['open_tcp'] == open_tcp and d['open_udp'] == open_udp:
            index = i
            break
    
    return index


def main():
    """main function"""
    if len(sys.argv) != 3:
        print("Usage: masscan_summary_report.py <directory> <output file>")
        sys.exit(1)
    
    directory = sys.argv[1]
    output_file = sys.argv[2]
    if not os.path.isdir(directory):
        print("[-] path provided is not a directory")
        sys.exit(1)

    print("[*] summarizing %s" % directory)
    # data = [{'target': network, 'open_tcp': ports, 'open_udp': ports, 'sources': [source1, source2, ...]},
    # ]
    data = []
    for f in os.listdir(directory):
        if f.endswith(".csv"):
            path = os.path.join(directory, f)
            print('[*] processing %s' % path)
            with open(path, 'r', newline="") as csv_fd:
                reader = csv.reader(csv_fd, dialect='excel')
                header = next(reader)
                for row in reader:
                    target = row[0]
                    source = row[1]
                    open_tcp = row[2]
                    open_udp = row[3]
                    index = get_matching_index(data, target, open_tcp, open_udp)
                    if index is not None:
                        data[index]['sources'].append(source)
                    else:
                        data.append({
                            'target': target,
                            'open_tcp': open_tcp,
                            'open_udp': open_udp,
                            'sources': [source]
                        })
    
    # data cleanup
    for d in data:
        sources = "; ".join(d['sources'])
        d['sources'] = sources
        d['network_id'] = int(ipaddress.IPv4Network(d['target']).network_address)

    # write the summary report
    field_names = ['network_id', 'target', 'sources', 'open_tcp', 'open_udp']
    with open(output_file, 'w', newline="") as csv_fd:
        writer = csv.DictWriter(csv_fd, fieldnames=field_names)
        writer.writeheader()
        for d in data:
            writer.writerow(d)


if __name__ == "__main__":
    main()