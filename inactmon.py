#!/usr/bin/python

import sys
import signal
import os, os.path
import stat
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

DEFAULT_MAX_CLIENTS = 5
DEFAULT_SOCKET_FILE = '/tmp/inactmon.sock'

class sockServer(threading.Thread):
	sockFile = None
	maxClients = None
	sock = None
	cliHandler = None

	class clientsHandler(threading.Thread):
		queue = None
		clients = []

		def __init__(self, queue):
			self.queue = queue
			threading.Thread.__init__(self)
			print "clientsHandler:init:done"

		def run(self):
			print "clientsHandler:loop"
			deadClients = []
			while True:
				message = self.queue.get()
				print "clientsHander: got message"
				for client in self.clients:
					try:
						client.send(message+"\n")
						print "Sent message"
					except KeyboardInterrupt:
						print "killed..."
						break
					except:
						print "client died?:"+str(sys.exc_info()[0])
						deadClients.append(client)
				self.queue.task_done()
			
				for client in deadClients:
					self.clients.remove(client)

		def append(self, connection):
			self.clients.append(connection)

	def __init__(self, sockFile, maxClients, queue):
		self.sockFile = sockFile
		self.maxClients = int(maxClients)

		threading.Thread.__init__(self)

		self.cliHandler = self.clientsHandler(queue)
		self.cliHandler.start()

	def run(self):
		self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		try:
		    os.remove(self.sockFile)
		except OSError:
		    pass
		except:
			print "os.remove exception:"+sys.exc_info()[0]

		self.sock.bind(self.sockFile)
		os.chmod(self.sockFile, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

		self.sock.listen(self.maxClients)
		while True:
			# get queue
			#try:
			connection, address = self.sock.accept()
			self.cliHandler.append(connection)
			#except:
			#	print "socket loop exception:"+str(sys.exc_info()[0])
			#	break
		self.sock.close()
		exit_gracefully()
			
class netMon(threading.Thread):
	class netMonMessenger:
		def __init__(self):
			debug("netMonMessenger:nothing to do")
		
		def parse(self,payload):
			rip = ImpactDecoder.EthDecoder().decode(payload)
			
			print rip
			proto = -1
			try:
				proto = rip.child().get_ip_p()
			except AttributeError:
				pass

			if proto == 6:
				debug('netMonMessenger:parse:is tcp!')
				return self.tcpParser(rip)
			if proto == 17:
				debug('netMonMessenger:parse:is UDP!')
				return self.udpParser(rip)
			if proto == 1:
				debug('netMonMessenger:parse:is ICMP')
				return 'icmp: not implemented'
			debug('netMonMessenger:parse:unknown ether type:'+str(rip.get_ether_type())+' with proto:'+str(proto))
			debug(rip)
			return self.message('error','proto not found')

		def message(self,status, message):
			if status is 'error':
				return "err:"+str(message)
			if status is 'info':
				return "info:"+str(message)
			return "meh"

		def tcpParser(self, rip):
			status = 'unknown'

			if rip.child().child().get_ACK():
				status = 'ack'
			if rip.child().child().get_SYN():
				status = 'syn'
			if rip.child().child().get_FIN():
				status = 'fin'
			if rip.child().child().get_RST():
				status = 'rst'

	#		macAddr = rip.as_eth_addr(rip.get_ether_shost())
			dstAddr = rip.child().get_ip_dst()
			srcAddr = rip.child().get_ip_src()
			srcPort = str(rip.child().child().get_th_sport())
			dstPort = str(rip.child().child().get_th_dport())
			seq = str(rip.child().child().get_th_seq())
			
			

			message = 'tcp:'+status+':'+srcAddr+':'+srcPort+':'+dstAddr+':'+dstPort

			return message

		def udpParser(self, rip):
			status = 'unknown'

			
			dstAddr = rip.child().get_ip_dst()
			srcAddr = rip.child().get_ip_src()
			srcPort = str(rip.child().child().get_uh_sport())
			dstPort = str(rip.child().child().get_uh_dport())
			
			message = 'udp:'+srcAddr+':'+srcPort+':'+dstAddr+':'+dstPort

			return message
	args = None
	ipAddresses = None

	def __init__(self,args,ipAddresses,myqueue):
		self.args = args
		self.ipAddresses = ipAddresses
		self.myqueue = myqueue
		threading.Thread.__init__(self)
		debug("netMon:init")

	def run(self):
		debug("netMon:run")
		messenger = self.netMonMessenger()

		# Arguments here are:
		#   device
		#   snaplen (maximum number of bytes to capture _per_packet_)
		#   promiscious mode (1 for true)
		#   timeout (in milliseconds)
	
		cap = pcapy.open_live(self.args.interface, 1500, 0, 0)
		if pcapy.DLT_EN10MB != cap.datalink():
			print "Interface is not ethernet based. Quitting..."
			return; # this should exit the thread..?

	# !!!
		print "%s: net=%s, mask=%s, addrs=%s" % (self.args.interface, cap.getnet(), cap.getmask(), str(self.ipAddresses))

		debug('Setting filter')
	# !!! improve filter
		cap.setfilter('tcp[13] = 2')

		debug('Waiting for packet...')
		while True:
			try:
				(header, payload) = cap.next()
			except:
				print "cap.next() exception:"+sys.exc_info()[0]

			message = messenger.parse(payload)
			debug(message)
			# queueMessages.put(message)
			self.myqueue.put(message)

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

def log(message):
	debug("LOG:"+str(message))
	# print "LOG:"+str(message)

def debug(message):
	global args
	if args.verbose:
		print 'DEBUG:'+str(message)

def checkInterface(iface):
	ipAddresses = [] 

	# check if there are interfaces available with pcapy
	try:
		ifs = pcapy.findalldevs()
	except pcapy.PcapError:
		print "Unable to get interfaces. Are you running as root?"
		sys.exit(1)

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


	
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGHUP, signal_handler)

parser = argparse.ArgumentParser(description='Monitor connection attempts.')

parser.add_argument('-i','--interface', 
	dest='interface', 
	required=True, 
	metavar='iface', 
	help='Interface to capture on.')

parser.add_argument('-s','--promiscuous', 
	dest='promiscuous', 
	required=False,  
	action='store_true',
	help='Set the capture interface to promiscuous. Might be needed by some options.')

parser.add_argument('-f','--socketFile', 
	dest='socketFile', 
	required=False, 
	metavar='file', 
	default=DEFAULT_SOCKET_FILE,
	help='File to listen for clients(default is '+str(DEFAULT_SOCKET_FILE)+').')

# IMPLEMENT!
# !!! implement file
# parser.add_argument('-p', '--port',
#	dest='port',
#	required=False,
#	metavar='port',
#	default=DEFAULT_PORT,
#	help='Port to listen for clients. If a file is specified will create socket at file(default is '+str(DEFAULT_PORT)+').')

parser.add_argument('-c','--conf', 
	required=False, 
	dest='config',
	type=file, 
	metavar='config-file',
	help='File holding the configuration.')

# IMPLEMENT!
# !!! implement in log function
parser.add_argument('-l','--log', 
	required=False, 
	dest='log',
	type=file, 
	metavar='log-file',
	help='File to log to.')

# IMPLEMENT
parser.add_argument('-m','--max-clients', 
	required=False, 
	dest='maxClients', 
	metavar='clients',
	default=DEFAULT_MAX_CLIENTS,
	help='Number of allowed clients(default is '+str(DEFAULT_MAX_CLIENTS)+').')

parser.add_argument('-v','--verbose', 
	required=False, 
	dest='verbose', 
	action='store_true', 
	help='More output.')

# IMPLEMENT: do not go to background ?
parser.add_argument('-d','--debug', 
	required=False, 
	dest='debug', 
	action='store_true', 
	help='Show all output.')

# IMPLEMENT
parser.add_argument('-q','--quiet', 
	required=False, 
	dest='verbose', 
	action='store_false', 
	help='Show less output(default)', 
	default=True)




args = parser.parse_args()
verbose = args.verbose

myqueue = Queue.Queue()

debug('Checking interface '+str(args.interface))
ipAddresses = checkInterface(args.interface)

debug('Starting sockServer thread')
sockServer_thread = sockServer(args.socketFile, args.maxClients, myqueue)
sockServer_thread.setDaemon(True)
sockServer_thread.start()


debug('Starting netMon thread')
netMon_thread = netMon(args, ipAddresses, myqueue)
netMon_thread.setDaemon(True)
netMon_thread.start()

#!! does nothing, could have been a thread..
while True:
	time.sleep(10)
	print '.' 
