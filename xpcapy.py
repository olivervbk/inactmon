#!/usr/bin/python

import sys
import signal
import os, os.path
import argparse

import time
import datetime

import SocketServer
import socket
import threading
import Queue

import netifaces
import pcapy
import impacket
from impacket import ImpactDecoder

MAX_CLIENTS = 5
DEFAULT_PORT = 9123

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
	pass

class MyTCPHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		global myqueue
		index = myqueue.init()
		if index == False:
			self.request.send("clients exceed max")
			return

		while True:
			message = myqueue.get(index)
			try:
				self.request.send(message)
				print "Sent message"
			except:
				print "Client died..."
				break
		myqueue.release(index)

def tcpServer(host, port, max_clients):
	debug("tcpServer:start")
	server = ThreadedTCPServer( (str(host),int(port)), MyTCPHandler)
	server.serve_forever()
	debug("tcpServer:stop")

def netMon(iface, ipAddresses):
	global myqueue
	debug("netMon:start")

	# Arguments here are:
	#   device
	#   snaplen (maximum number of bytes to capture _per_packet_)
	#   promiscious mode (1 for true)
	#   timeout (in milliseconds)

	cap = pcapy.open_live(iface, 1500, 0, 0)
	if pcapy.DLT_EN10MB != cap.datalink():
		print "Interface is not ethernet based. Quitting..."
		return; # this should exit the thread..?

# !!!
	print "%s: net=%s, mask=%s, addrs=%s" % (iface, cap.getnet(), cap.getmask(), str(ipAddresses))

	debug('Setting filter')
# !!! improve filter
	cap.setfilter('tcp[13] = 2')

	debug('Waiting for packet...')
	while True:
		(header, payload) = cap.next()

		rip = ImpactDecoder.EthDecoder().decode(payload)
#		macAddr = rip.as_eth_addr(rip.get_ether_shost());
		dstAddr = rip.child().get_ip_dst()
		srcAddr = rip.child().get_ip_src()
		srcPort = str(rip.child().child().get_th_sport())
		dstPort = str(rip.child().child().get_th_dport())

		message = srcAddr+":"+srcPort+"->"+dstAddr+":"+dstPort
		debug(message)
		# queueMessages.put(message)
		myqueue.add(message)

	debug("netMon:stop")


def signal_handler(signal_recv, frame):
	if signal_recv == signal.SIGINT:
		exit_gracefully()

	if signal_recv == signal.SIGHUP:
		reload_config()

def exit_gracefully():
	print "\nexiting..."
# !!! this is not very graceful =/
	sys.exit(0)

def reload_config():
	print "\nreload config"

def debug(message):
	global verbose
	if(verbose):
		print "DEBUG:"+str(message)

def log(message):
	debug("LOG:"+str(message))
	# print "LOG:"+str(message)

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

class myQueue:
	maxclients = 0
	queue = []
	available = []

	def __init__(self,maxclients, maxsizes):
		self.maxclients = maxclients
		for i in range(0, maxclients):
			self.queue.insert(i, Queue.Queue(maxsizes))
			self.available.append(i)

	def init(self):
		if len(self.available) == 0:
			return False
		return self.available.pop()
		
	def release(self,index):
		self.available.append(index)

	def add(self,message):
		for i in range(0,self.maxclients):
			self.queue[i].put_nowait(message)
		
	def get(self,index):
		return self.queue[index].get()
	
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGHUP, signal_handler)

parser = argparse.ArgumentParser(description='Monitor connection attempts.')
parser.add_argument('-i','--interface', 
	dest='interface', 
	required=True, 
	metavar='iface', 
	help='Interface to listen on.')

# IMPLEMENT!
# !!! implement file
parser.add_argument('-p', '--port',
	dest='port',
	required=False,
	metavar='port',
	default=DEFAULT_PORT,
	help='Port to listen for clients. If a file is specified will create socket at file.')

# IMPLEMENT!
# !!! implement in log function
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
	help='Show less output(default)', 
	default=True)




args = parser.parse_args()
verbose = args.verbose

myqueue = myQueue(MAX_CLIENTS, 0)

debug('Checking interface '+str(args.interface))
ipAddresses = checkInterface(args.interface)

debug('Starting tcpServer thread')
tcpServer_thread = threading.Thread(target=tcpServer, args=('localhost',int(args.port), MAX_CLIENTS))
tcpServer_thread.setDaemon(True)
tcpServer_thread.start()
debug("tcpServer running in thread:"+str(tcpServer_thread.getName()))


debug('Starting netMon thread')
netMon_thread = threading.Thread(target=netMon, args=(args.interface, ipAddresses))
netMon_thread.setDaemon(True)
netMon_thread.start()
debug("netMon running in thread:"+str(netMon_thread.getName()))

#!! does nothing, could have been a thread..
while True:
	time.sleep(10)
	print '.' 
