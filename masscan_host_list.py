# masscan_host_list.py
#
# Takes a masscan file and creates a 
# list of hosts accessible for each unique port
# in the results file.
#
# Usage: masscan_host_list.py <masscan file> <output directory>
#   If the output directory exists, it will not create it.
#

import argparse
import os


def parse_line(line, output_directory):
    """Parse a masscan file line."""
    if line[0] == "#":
        return None
    
    state, proto, port, host, ident = line.split()
    output_file = os.path.join(output_directory, "%s.txt" % port)
    
    # write the host to the output file
    with open(output_file, 'a') as host_fd:
        host_fd.write("%s\n" % host)

    return True


def main():
    """The main function."""

    parser = argparse.ArgumentParser(description='Creates a list of hosts from a masscan file.')
    parser.add_argument('masscan_file', help='Masscan file to parse.')
    parser.add_argument('output_directory', help='Directory to put output files into, must not exist.')
    args = parser.parse_args()

    masscan_file = args.masscan_file
    output_directory = args.output_directory

    # test arguments
    assert os.path.isfile(masscan_file)
    assert not os.path.isdir(output_directory)

    # make the directory
    os.mkdir(output_directory, '0755')

    with open(masscan_file, 'r') as masscan_fd:
        for line in masscan_fd:
            parse_line(line, output_directory)


if __name__ == "__main__":
    main()
