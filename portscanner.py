#!/usr/bin/python
#
# Python port scanner
#
# Usage: portscanner.py <targets> <port list>
#	targets: 	a list of IP addresses, host names, or network IDs
#				separated by commas. Valid formats:
#					192.168.1.1 - individual IP address
#					192.168.1.0/24 - network id and subnet mask
#					gateway.localdomain.local - hostname
#	port list:	a list of TCP ports to scan, separated by commas
#

import re
import socket
import sys
import time


def main():
	"""main function"""

	#print("sys.argv = [%s]" % (sys.argv))
	if len(sys.argv) != 3:
		print("[-] Illegal number of arguments")
		print_help()
		sys.exit(1)

	targets = sys.argv[1]
	ports = sys.argv[2]

	print("[*] port_list = [%s], targets = [%s]" % (ports, targets))

	# create lists of ports and targets
	port_list = ports.split(',')
	target_list = targets.split(',')

	# traverse the list of targets, first identify
	# the type of entry (IP address, network + mask, hostname)
	# expand or resolved into an IP address list, combine
	# into a full list of target IP addresses
	all_ip_addresses = []
	for t in target_list:
		if re.match('\d+\.\d+\.\d+\.\d+', t):
			# ip address
			all_ip_addresses.append(t)
		elif re.match('\d+\.\d+\.\d+\.\d+/\d+', t):
			# network and subnet mask
			network = ipaddress.IPv4Network(t)
			ipaddresses = list(network.hosts())
			for i in ipaddresses:
				all_ip_addresses.append(str(i))
		else:
			# assume hostname if no match above
			# get the IP address for the hostname
			try:
				address = socket.gethostbyname(t)
			except socket.gaierror:
				print('[-] cannot resolve hostname: %s' % (t))
				sys.exit(1)
			all_ip_addresses.append(address)

	# with the list of all addresses perform the scan
	results = {}
	for i in all_ip_addresses:
		start = time.time()
		address_port_results = {}
		for p in port_list:
			port = int(p)
			address_port_results[p] = 'closed'
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				result = sock.connect((i, port))
				if result is None:
					address_port_results[p] = 'open'
				sock.close()
			except socket.error:
				print("[-] could not connect to server %s:%s" % (i, p))
			except socket.gaierror:
				print("[-] error resolving hostname %s:%s" % (i, p))
			except socket.timeout:
				print("[-] timeout connecting to %s:%s" % (i, p))
			except ConnectionRefusedError:
				address_port_results[p] = 'closed'
			except:
				print("[-] unknown error for %s:%s" % (i, p))

		results[i] = address_port_results
		end = time.time()
		elapsed_time = end - start
		print("[*] performed scan on %s in %f seconds" % (i, elapsed_time))

	print(results)

def print_help():
	"""prints a help message"""

	print("""Usage: portscanner.py <targets> <port list>
targets: 	a list of IP addresses, host names, or network IDs
			separated by commas. Valid formats:
				192.168.1.1 - individual IP address
				192.168.1.0/24 - network id and subnet mask
				gateway.localdomain.local - hostname
port list:	a list of TCP ports to scan, separated by commas""")


if __name__ == "__main__":
	main()