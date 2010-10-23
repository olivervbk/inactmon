#!/usr/bin/python

import sys
import signal
import os, os.path

import time
import datetime

import socket
import threading
import Queue
import SocketServer

import argparse

import netifaces

import pcapy

import impacket
from impacket import ImpactDecoder

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):
	def setup(self):
		print "thread:start"
		
	def handle(self):
		while True:
			message = messages.get()
		
			threadName = threading.currentThread().getName()
			if message == 'stop':
				print threadName+" stopping"
				break
 
			response = "%s: %s\n" % (threadName, message)
		
			print response
			self.request.send(response)
			messages.task_done()

	def finish(self):
		print "thread:stop"

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
	pass

def signal_handler(signal_recv, frame):
	if signal_recv == signal.SIGINT:
		print "\nexiting..."
		messages.put('stop')
		server.shutdown()
		print 'waiting for threads to finish'
		while threading.activeCount:
			print '.',
			time.sleep(1)

		sys.exit(0)

	if signal_recv == signal.SIGHUP:
		print "\nreload config"

messages = Queue.Queue(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGHUP, signal_handler)

parser = argparse.ArgumentParser(description='Monitor connection attempts.')
parser.add_argument('-i','--interface', 
	dest='interface', 
	required=True, 
	metavar='iface', 
	help='Interface to listen on.')

# IMPLEMENT!
parser.add_argument('-p', '--port',
	dest='port',
	required=False,
	metavar='port',
	default='9123',
	help='Port to listen for clients. If a file is specified will create socket at file.')

# IMPLEMENT!
parser.add_argument('-l','--log', 
	required=False, 
	dest='log',
	type=file, 
	metavar='log-file',
	help='File to log to.')

# IMPLEMENT!
parser.add_argument('-v','--verbose', 
	required=False, 
	dest='verbose', 
	action='store_true', 
	help='More output.')

# IMPLEMENT!
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
		print "DEBUG:"+str(message)

def log(message):
	print "LOG:"+str(message)

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
	
debug('Checking interface '+str(args.interface))
ipAddresses = checkInterface(args.interface)

debug('Setting socket on '+str(args.port))
messages.put('start')

server = ThreadedTCPServer(('localhost', int(args.port)), ThreadedTCPRequestHandler)
server_thread = threading.Thread(target=server.serve_forever)
server_thread.setDaemon(True)
server_thread.start()

debug("Server running in thread:"+str(server_thread.getName()))

# Arguments here are:
#   device
#   snaplen (maximum number of bytes to capture _per_packet_)
#   promiscious mode (1 for true)
#   timeout (in milliseconds)
debug('Opening interface for sniffing')
# MAKE ARGUMENTS user specifiable ?
cap = pcapy.open_live(args.interface, 1500, 0, 0)
if pcapy.DLT_EN10MB != cap.datalink():
	print "Interface is not ethernet based. Quitting..."
	sys.exit(1)

print "%s: net=%s, mask=%s, addrs=%s" % (args.interface, cap.getnet(), cap.getmask(), str(ipAddresses))

debug('Setting filter')
cap.setfilter('tcp[13] = 2 ')

debug('Waiting for packet...')
(header, payload) = cap.next()
while header:
	rip = ImpactDecoder.EthDecoder().decode(payload)
	macAddr = rip.as_eth_addr(rip.get_ether_shost());
	dstAddr = rip.child().get_ip_dst()
	srcAddr = rip.child().get_ip_src()
	srcPort = str(rip.child().child().get_th_sport())
	dstPort = str(rip.child().child().get_th_dport())

	message = srcAddr+":"+srcPort+"->"+dstAddr+":"+dstPort
	print message
	messages.put(message)

	(header, payload) = cap.next()

	
