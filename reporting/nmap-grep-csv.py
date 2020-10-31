#
# Requires Python 3.x
#
# Takes nmap greppable output and turns
# it into a CSV file
# Usage:
# nmap-grep-csv.py [--overwrite] <input file/directory> <output file>
#   --overwrite:              by default, the output file is appended to, use this switch to 
#                             overwrite the output file rather than append to it
#   input file/directory:     can be a single file or a directory, if it is a directory
#                             the directory contents will be searched for files with the
#                             .gnmap extension

import csv
import os
import sys


class NmapHostStatus:
    
    def __init__(self, host, status):
        self.host = host
        self.status = status
        self.ports = []

    def add_port(self, port, port_status, protocol, name, service):
        self.ports.append([port, port_status, protocol, name, service])
    
    def add_port_gnmap(self, port_string):
        """e.g. '53/open|filtered/udp//domain///,'
                '22/open/tcp//ssh//OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)/'"""
        parts = port_string.split('/')
        port = parts[0]
        port_status = parts[1]
        protocol = parts[2]
        name = parts[4]
        service = parts[6]
        self.add_port(port, port_status, protocol, name, service)
    
    def csv_list(self, source):
        """returns a list of rows to be inserted into a 
        CSV file"""
        result = []
        result.append({'source': source, 
                       'destination': self.host,
                       'status': self.status,
                       'port': None,
                       'port_status': None,
                       'protocol': None,
                       'name': None,
                       'service': None})
        for port in self.ports:
            result.append({'source': source,
                           'destination': self.host,
                           'status': self.status,
                           'port': port[0],
                           'port_status': port[1],
                           'protocol': port[2],
                           'name': port[3],
                           'service': port[4]})
        return result
    
    def __repr__(self):
        """returns a string with the object's data"""
        result = "%s (%s):\n" % (self.host, self.status)
        for port in self.ports:
            result += "\t%s %s %s %s %s\n" % (port[0], port[1], port[2], port[3], port[4])
        result += "\n"
        return result


def main():
    """main function"""
    # set options
    overwrite = False

    # get arguments
    if len(sys.argv) < 2:
        print("[-] Error: invalid number of arguments")
        print_help()
        sys.exit(1)
    if sys.argv[1] == '--overwrite':
        overwrite = True
        input_path = sys.argv[2]
        output_file = sys.argv[3]
    else:
        input_path = sys.argv[1]
        output_file = sys.argv[2]

    # check if the input provided is a directory or a single file
    if os.path.isdir(input_path):
        print("%s is a directory" % input_path)
        search_string = ".gnmap"
        files = os.listdir(input_path)
        input_files = [ os.path.join(input_path, f) for f in files if search_string in f ]
    else:
        input_files = [input_path]

    # parse all input files
    for input_file in input_files:
        print("gathering data from %s" % input_file)
        filename, extension = os.path.basename(input_file).split('.')

        # open files for reading and writing 
        in_file = open(input_file, 'r')
        if overwrite:
            out_file = open(output_file, 'w', newline='')
        else:
            out_file = open(output_file, 'a', newline='')

        # get contents of the input file
        file_contents = in_file.read()
        in_file.close()
        lines = file_contents.split('\n')

        # gather the data from the file
        data = []
        # CSV fields 
        # host, status, port, port_status,protocol,name
        found_host_section = False
        for num, line in enumerate(lines):
            if 'Host: ' in line and 'Status: ' in line:
                _, host, _, status = line.split(' ')
                host_data = NmapHostStatus(host, status)
                found_host_section = True
            elif 'Host: ' in line and 'Ports: ' in line:
                sections = line.split('\t')

                if not found_host_section:
                    _, host, _ = sections[0].split(' ')
                    host_data = NmapHostStatus(host, 'up')

                parts = sections[1].split(':', maxsplit=1)
                ports = parts[1].split("/, ")
                for port_info in ports:
                    try:
                        host_data.add_port_gnmap(port_info)
                    except IndexError:
                        print("IndexError with line %d [%s]" % (num, line))

                        sys.exit(1)
                data.append(host_data)
                found_host_section = False
        
        # now write the data to the output file
        fieldnames = ['source', 'destination', 'status', 'port', 'port_status', 'protocol', 'name', 'service']
        nmap_writer = csv.DictWriter(out_file, fieldnames=fieldnames)
        out_file_size = os.fstat(out_file.fileno()).st_size
        if overwrite or out_file_size == 0:
            nmap_writer.writeheader()
        for d in data:
            for row in d.csv_list(filename):
                nmap_writer.writerow(row)

        out_file.close()


def print_help():
    """prints a help message"""
    print("""Usage:
nmap-grep-csv.py [--overwrite] <input file/directory> <output file>
  --overwrite:              by default, the output file is appended to, use this switch to 
                            overwrite the output file rather than append to it)
  
  input file/directory:     can be a single file or a directory, if it is a directory
                            the directory contents will be searched for files with the
                            .gnmap extension""")

 

if __name__ == "__main__":
    main()