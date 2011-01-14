#!/usr/bin/python

import sys
import signal
import os, os.path
import stat
import argparse
import logging

import time
import datetime

import socket
import threading
import Queue

import netifaces
import pcapy
import impacket
from impacket import ImpactDecoder

#TODO:choose whether to go to background or not
#TODO:implement filter system->name-rules (iface? =/)

#FIXME:does not exit gracefully

# --- Default Values ---
DEFAULT_MAX_CLIENTS = 5
DEFAULT_SOCKET_FILE = '/tmp/inactmon.sock'
DEFAULT_VERBOSE_LEVEL = 'warn'

# --- Classes ---
# NullHandler: used to make loggers not output(quiet)
class NullHandler(logging.Handler):
    def emit(self, record):
        pass

class sockServer(threading.Thread):
	class clientsHandler(threading.Thread):
		queue = None
		clients = []
		logger = None

		def __init__(self, queue):
			self.queue = queue
			self.logger = logging.getLogger('console.sockServer.clientsHandler')
			threading.Thread.__init__(self)
			self.logger.debug("init:done")

		def run(self):
			self.logger.debug( "loop")
			deadClients = []
			while True:
				try:
					message = self.queue.get()
				except KeyboardInterrupt:
					self.logger.info("killed..")
					return

				self.logger.debug("got message")
				for client in self.clients:
					try:
						client.send(message+"\n")
						self.logger.debug("Sent message to client")
					except KeyboardInterrupt:
						self.logger.info("killed...")
						return
					except:
						self.logger.info( "client died?:"+str(sys.exc_info()[0]))
						deadClients.append(client)
				self.queue.task_done()
			
				self.logger.debug("removing dead clients...")
				for client in deadClients:
					self.clients.remove(client)

				#clear deadClients again
				deadClients = []

		def append(self, connection):
			self.logger.debug("appended connection")
			self.clients.append(connection)

	sockFile = None
	maxClients = None
	sock = None
	cliHandler = None
	logger = None

	def __init__(self, sockFile, maxClients, queue):
		self.sockFile = sockFile
		self.maxClients = int(maxClients)

		self.logger = logging.getLogger('console.sockServer')

		self.cliHandler = self.clientsHandler(queue)
		self.cliHandler.start()

		threading.Thread.__init__(self)

		self.logger.debug("init:done")
		#self.run() DO NOT


	def run(self):
		self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		try:
		    os.remove(self.sockFile)
		except OSError:
		    pass
		except:
			print "os.remove exception:"+sys.exc_info()[0]
			exit_gracefully()

		self.sock.bind(self.sockFile)
		os.chmod(self.sockFile, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

		self.logger.info("Listening for connections...")
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
		self.logger.warn("exiting gracefully")
		exit_gracefully()
			
class netMon:
	class netMonMessenger:
		logger = None
		def __init__(self):
			self.logger = logging.getLogger('console.netMon.netMonMessenger')
			self.logger.debug("init")
		
		def parse(self,payload,name):
			self.logger.debug("got payload from "+name)
			rip = ImpactDecoder.EthDecoder().decode(payload)

			print rip
	
			proto = -1			
			try:
				proto = rip.child().get_ip_p()
			except AttributeError:
				pass

			#FIXME:add proto constant names instead of numbers =/
			if proto == 6:
				self.logger.debug('parse:is tcp!')
				return self.tcpParser(rip)
			if proto == 17:
				self.logger.debug('parse:is UDP!')
				return self.udpParser(rip)
			if proto == 1:
				self.logger.debug('parse:is ICMP')
				return self.icmpParser(rip)

			self.logger.debug('parse:unknown ether type:'+str(rip.get_ether_type())+' with proto:'+str(proto))
			self.logger.debug(rip)
			return self.message('error','proto not found')

		def message(self,status, message):
			if status is 'error':
				return "err:"+str(message)
			if status is 'info':
				return "info:"+str(message)
			return "meh"

		def icmpParser(self, rip):
			status = 'unknown'
			#FIXME:should get only req

			dstAddr = rip.child().get_ip_dst()
			srcAddr = rip.child().get_ip_src()
			icmpType = rip.child().child().get_icmp_type()

			if(icmpType == rip.child().child().ICMP_ECHO):
				status = 'echo'
			if(icmpType == rip.child().child().ICMP_ECHOREPLY):
				status = 'reply'

			return 'icmp:'+srcAddr+':'+dstAddr+':'+status

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

	class netMonFilter(threading.Thread):
		args = None
		ipAddresses = None
		myqueue = None
		messenger = None
		logger = None
		name = None
		rule = None

		def __init__(self,args,ipAddresses,myqueue,messenger,name,rule):
			#FIXME: args really needed ? =/
			self.args = args
			self.ipAddresses = ipAddresses
			self.myqueue = myqueue
			self.messenger = messenger
			self.name = name
			self.rule = rule
			self.logger = logging.getLogger('console.netMon.'+self.name)
			threading.Thread.__init__(self)
			self.logger.debug("init:done")

		def run(self):
			self.logger.debug("run")

			cap = pcapy.open_live(self.args.interface, 1500, 0, 0)
			
			self.logger.debug('Setting filter')
			try:
				cap.setfilter(self.rule)
			except:
				print "Unable to set rule '"+self.rule+"' for filter '"+self.name+"'"
				exit_gracefully()

			self.logger.info('Waiting for packet...')
			while True:
				try:
					(header, payload) = cap.next()
				except:
					print "cap.next() exception:"+str(sys.exc_info()[0])
					exit_gracefully()

				message = self.messenger.parse(payload, self.name)
				self.logger.debug("msg rcvd: "+str(message))
				self.myqueue.put(message)

			self.logger.info("stopping...")

	args = None
	ipAddresses = None
	logger = None

	def __init__(self,args,ipAddresses,myqueue,filters):
		self.args = args
		self.ipAddresses = ipAddresses
		self.myqueue = myqueue
		self.logger = logging.getLogger('console.netMon')
		#threading.Thread.__init__(self)
		self.logger.debug("init:done")
		self.run()

	def run(self):
		self.logger.debug("run")
		messenger = self.netMonMessenger()

		# Arguments here are:
		#   device
		#   snaplen (maximum number of bytes to capture _per_packet_)
		#   promiscious mode (1 for true)
		#   timeout (in milliseconds)
	
		self.logger.debug("testing interface(s?)")
		cap = pcapy.open_live(self.args.interface, 1500, 0, 0)

		#2DO:this test should only be made once!
		if pcapy.DLT_EN10MB != cap.datalink():
			print "Interface is not ethernet based. Quitting..."
			exit_gracefully()
			return; # this should exit the thread..?
		#remove cap after test ? =/

		# FIXME:remove this line?
		print "%s: net=%s, mask=%s, addrs=%s" % (self.args.interface, cap.getnet(), cap.getmask(), str(self.ipAddresses))

		self.logger.debug("starting filter engines")
		for oneFilter in filters:
			filter_thread = self.netMonFilter(args, ipAddresses, myqueue, messenger, oneFilter[0], oneFilter[1])	
			# filter_thread.setDaemon(True)
			filter_thread.start()

		self.logger.debug("done creating engines")
		

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

def signal_handler(signal_recv, frame):
	if signal_recv == signal.SIGINT:
		exit_gracefully()

	if signal_recv == signal.SIGHUP:
		reload_config()

def exit_gracefully():
	print "\nexiting..."
	logging.shutdown()
	print "should exit now =/"
# !!! this is not very graceful =/
	sys.exit(0)

def reload_config():
	print "\nreload config"
	
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
	type=str, 
	metavar='config-file',
	default=None,
	help='File holding the configuration.')

# IMPLEMENT!
# !!! implement in log function
parser.add_argument('-l','--log', 
	required=False, 
	dest='log',
	type=str, 
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
	type=str,
	default=DEFAULT_VERBOSE_LEVEL,
	help='More output(debug|info|warn|error|critical) Warn is default.')

# IMPLEMENT: do not go to background ?
parser.add_argument('-d','--debug', 
	required=False, 
	dest='debug', 
	action='store_true', 
	help='Show all output.')

# IMPLEMENT
parser.add_argument('-q','--quiet', 
	required=False, 
	dest='quiet', 
	action='store_true', 
	help='Show no output(overrides verbosity).', 
	default=False)


LEVELS = {'debug': logging.DEBUG,
          'info': logging.INFO,
          'warn': logging.WARNING,
          'error': logging.ERROR,
          'critical': logging.CRITICAL}

#parse args
args = parser.parse_args()

#start queue
myqueue = Queue.Queue()

if args.config is not None:
	print "Config load is not implemented yet"
	sys.exit(0)

#start loggers
log = logging.getLogger('log')

if args.log:
	print "File logging not implemented yet"
	sys.exit(0)

console = logging.getLogger('console')
# get verbose level
try:
	level = LEVELS[args.verbose]
	console.setLevel(level)
except KeyError:
	print "Verbose option '"+args.verbose+"' invalid."
	sys.exit(0)

#set handler and formatter
if not args.quiet:
	sh = logging.StreamHandler()
	sf = logging.Formatter("%(name)s - %(levelname)s - %(message)s")
	sh.setFormatter(sf)
	console.addHandler(sh)
else:
	nh = NullHandler()
	console.addHandler(nh)

console.debug('Checking interface '+str(args.interface))
ipAddresses = checkInterface(args.interface)

console.debug('Starting sockServer thread')
sockServer_thread = sockServer(args.socketFile, args.maxClients, myqueue)
sockServer_thread.start()

console.debug('Starting netMon')
filters = [['tcpSyn-test','tcp[13] = 2'], ['udp-test', 'udp port 53'], ['icmp-test','icmp']]
netMon(args, ipAddresses, myqueue,filters)

while 1:
	time.sleep(50)
	print "."
exit_gracefully()
