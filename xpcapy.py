#!/usr/bin/python

import sys
import signal
import datetime

import argparse

import netifaces

import pcapy

import impacket
from impacket import ImpactDecoder

def signal_handler(signal_recv, frame):
	if signal_recv == signal.SIGINT:
		print "\nexiting..."
		sys.exit(0)
	if signal_recv == signal.SIGHUP:
		print "\nreload config"

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGHUP, signal_handler)

parser = argparse.ArgumentParser(description='Monitor connection attempts.')
parser.add_argument('-i','--interface', 
	dest='interface', 
	required=True, 
	metavar='iface', 
	help='Interface to listen on.')

parser.add_argument('-l','--log', 
	required=False, 
	dest='log',
	type=file, 
	metavar='log-file',
	help='File to log to.')

parser.add_argument('-v','--verbose', 
	required=False, 
	dest='verbose', 
	action='store_true', 
	help='More output.')

parser.add_argument('-q','--quiet', 
	required=False, 
	dest='verbose', 
	action='store_false', 
	help='Show less', 
	default=True)

args = parser.parse_args()
verbose = args.verbose

def debug(message):
	global verbose
	if(verbose):
		print "DEBUG:".str(message)

def log(message):
	print "LOG:".str(message)

def checkInterface(iface):
	ipAddresses = [] 

	# check if there are interfaces available with pcapy
	ifs = pcapy.findalldevs()
	if 0 == len(ifs):
		print "No interfaces available."
		sys.exit(1)

	if not iface in ifs:
		print "Interface '%s' not found." % (iface)
		sys.exit(1)

	for ifaceName in netifaces.interfaces():
		try:
			addresses = netifaces.ifaddresses(ifaceName)[netifaces.AF_INET]
			for address in netifaces.ifaddresses(ifaceName)[netifaces.AF_INET]:
				if iface == 'any':
					ipAddresses.append(address['addr'])
				elif iface == ifaceName:
					ipAddresses.append(address['addr'])
		except KeyError:
			if iface == ifaceName:
				print "Interface '%s' is down." % (iface)
				sys.exit(1)
	return ipAddresses
	

ipAddresses = checkInterface(args.interface)

# Arguments here are:
#   device
#   snaplen (maximum number of bytes to capture _per_packet_)
#   promiscious mode (1 for true)
#   timeout (in milliseconds)

cap = pcapy.open_live(args.interface, 1500, 0, 0)
if pcapy.DLT_EN10MB != cap.datalink():
	print "Interface is not ethernet based. Quitting..."
	sys.exit(1)

print "%s: net=%s, mask=%s, addrs=%s" % (args.interface, cap.getnet(), cap.getmask(), str(ipAddresses))

cap.setfilter('tcp[13] = 2 ')

(header, payload) = cap.next()
while header:
	print ('%s: captured %d bytes, truncated to %d bytes') % (datetime.datetime.now(), header.getlen(), header.getcaplen())
	rip = ImpactDecoder.EthDecoder().decode(payload)
	macAddr = rip.as_eth_addr(rip.get_ether_shost());
	dstAddr = rip.child().get_ip_dst()
	srcAddr = rip.child().get_ip_src()
	print "dst:"+dstAddr
	print "src:"+srcAddr
#	print rip.child().child().get_port()
	print "src port"+str(rip.child().child().get_th_sport())
	print "dst port"+str(rip.child().child().get_th_dport())

	(header, payload) = cap.next()

	
