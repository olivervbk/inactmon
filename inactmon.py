#!/usr/bin/python

import sys
import signal
import os, os.path
import stat
import copy
import argparse
import logging

import time
import datetime

import socket
import threading
import Queue

import ConfigParser

import netifaces
import pcapy
import impacket
from impacket import ImpactDecoder

#TODO:ready a release! =/ and update website
#TODO:implement filter system->name-rules (iface! sets the incoming dst ip :D )
#TODO:set main thread to do something useful, sockServer?(blocks?)
#TODO:clean up logging system ? =/
#FIXME:do daemonic threads damage non-renewable system resources?(inet sockets?)(pcap resources?)

# --- Default Values ---
DEFAULT = {}
DEFAULT['max clients'] = 5
DEFAULT['socket file'] = '/tmp/inactmon.sock'
DEFAULT['verbose'] = 'warn'
DEFAULT['debug'] = False
DEFAULT['config'] = 'inactmon.conf' #FIXME:/etc/inactmon.conf
DEFAULT['log'] = 'inactmon.log'#FIXME:/var/log/inactmon.log

CURRENT = copy.deepcopy(DEFAULT) #damned objects...

# --- Classes ---
# NullHandler: used to make loggers not output(quiet)
class NullHandler(logging.Handler):
    def emit(self, record):
        pass

# Class that handles clients
class sockServer(threading.Thread):
	#This subclass handles the client comunication in a separate thread. Handles all clients,
	#not just one per instance...
	#Less elegant, though easier than the alternative, multiple inter-thread queues...
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
			deadClients = [] #lists clients to be removed because of death

			#Main loop: checks for new messages and sends them to all clients in list
			#Checks also if clients are still conected.
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
				self.queue.task_done() #kinda useless, required by queue
			
				self.logger.debug("removing dead clients...")
				for client in deadClients:
					self.clients.remove(client)

				#clear deadClients again
				deadClients = []

		#Called by owner to add more clients
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

		# run clienthandler thread
		self.cliHandler = self.clientsHandler(queue)
		self.cliHandler.setDaemon(True)
		self.cliHandler.start()

		threading.Thread.__init__(self)

		self.logger.debug("init:done")
		#self.run() DO NOT


	def run(self):
		#Create unix socket
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
			try:
#this may block
				connection, address = self.sock.accept()
				self.cliHandler.append(connection)
			except:
				print "socket loop exception:"+str(sys.exc_info()[0])
				break

		#The following will probably never run since sock.accept() blocks and this thread is 'killed' on exit
		self.sock.close()
		self.logger.warn("exiting gracefully")
		exit_gracefully()

# Class that handles filters	
class netMon:
	# Handles parsing of headers to send to clients, didn't need to be a class but probably better so.
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

			return 'icmp:'+status+':'+srcAddr+':'+dstAddr

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

	# Variable filter class
	class netMonFilter(threading.Thread):
		args = None
		ipAddresses = None
		myqueue = None
		messenger = None
		logger = None
		name = None
		rule = None

		def __init__(self,myqueue,messenger,name,rule,iface):
			#FIXME: args really needed ? =/ just interface is needed... and should be specified by config
			self.iface = iface
			self.name = name
			self.rule = rule

			self.myqueue = myqueue
			self.messenger = messenger

			self.ipAddresses = self.checkInterface(iface)
			self.logger = logging.getLogger('console.netMon.'+self.name)

			threading.Thread.__init__(self)

			self.logger.debug("init:done")

		def run(self):
			self.logger.debug("run")

			# Arguments here are:
			#   device
			#   snaplen (maximum number of bytes to capture _per_packet_)
			#   promiscious mode (1 for true)
			#   timeout (in milliseconds)

			cap = pcapy.open_live(self.iface, 1500, 0, 0)
			if pcapy.DLT_EN10MB != cap.datalink():
				print "Interface is not ethernet based. Quitting..."
				thread.interrupt_main()
			
			#print "%s: net=%s, mask=%s, addrs=%s" % (self.args.interface, cap.getnet(), cap.getmask(), str(self.ipAddresses))

			self.logger.debug('Setting filter')
			try:
				cap.setfilter(self.rule)
			except:
				print "Unable to set rule '"+self.rule+"' for filter '"+self.name+"'"
				exit_gracefully()

			self.logger.info('Waiting for packet...')
			while True:
				try:
#this may block
					(header, payload) = cap.next()
				except:
					print "cap.next() exception:"+str(sys.exc_info()[0])
					exit_gracefully()

				message = self.messenger.parse(payload, self.name)
				self.logger.debug("msg rcvd: "+str(message))
				self.myqueue.put(message)

			self.logger.info("stopping...")

		def checkInterface(self, iface):
			ipAddresses = [] 

			# check if there are interfaces available with pcapy
			try:
				ifs = pcapy.findalldevs()
			except pcapy.PcapError:
				print "Unable to get interfaces. Are you running as root?"
				thread.interrupt_main()

			if 0 == len(ifs):
				print "No interfaces available."
				thread.interrupt_main()

			if not iface in ifs:
				print "Interface '%s' not found." % (iface)
				thread.interrupt_main()

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
						thread.interrupt_main()
			return ipAddresses
	args = None
	ipAddresses = None
	logger = None

	def __init__(self,myqueue,filters):
		self.myqueue = myqueue
		self.filters = filters

		self.logger = logging.getLogger('console.netMon')

		#FIXME:clean this
		#threading.Thread.__init__(self) #this is not a thread anymore
		self.logger.debug("init:done")
		self.run() #since it is not a thread

	def run(self):
		self.logger.debug("run")
		messenger = self.netMonMessenger()

		self.logger.debug("starting filter engines")
		for oneFilter in filters:
			filter_thread = self.netMonFilter(myqueue, messenger, oneFilter[0], oneFilter[1], oneFilter[2])	
			filter_thread.setDaemon(True)
			filter_thread.start()

		self.logger.debug("done creating engines")
		
#FIXME:set as function in netMon


def signal_handler(signal_recv, frame):
	if signal_recv == signal.SIGINT:
		exit_gracefully()

	if signal_recv == signal.SIGHUP:
		reload_config()

def exit_gracefully():
#FIXME:remove these prints
	print "\nexiting..."
	logging.shutdown()
	print "exit_gracefully is done!"

#FIXME:socket.accept and pcapy.next are blocking... AND signals are only treated in the main thread..,
#	this could lead to problems when dealing with non reusable system resources(like inet sockets =/)
#	With daemonic threads they are killed automatically and silently... I guess...

#	Alternatives:
#	signal.alarm() # does nothing =/ must implement with alarm.pause? but socket.accept is blocking...
#	os.kill(os.getpid(), signal.SIGKILL) # kills all threads
#	os.kill(os.getpid(), signal.SIGTERM) # terminates all threads
#	os._exit(0) # kills all threads
#	sys.exit(0) # does only exit current thread(main)

	sys.exit(0)

def reload_config():
#TODO:implement
	print "\nreload config"
	
#FIXME:separate the rest into MAIN

#Set signal handling
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGHUP, signal_handler)

#Get config file to load defaults from
optionNum = -1
try:
	optionNum = sys.argv.index('-c')
except ValueError:
	try:
		optionNum = sys.argv.index('--conf')
	except ValueError:
		pass
if(optionNum != -1):
	CURRENT['config'] = sys.argv[optionNum+1]

#Load config file
configParser = ConfigParser.ConfigParser()
#FIXME:try!
configParser.readfp(open(CURRENT['config']))

allowedConfigIndexes = ['socket file', 'log', 'max clients', 'debug', 'verbose']

try:
	configParser.sections().index('global')
except ValueError:
	pass
else:
	print "parsing global configurations"
	for item in configParser.items('global'):
		print item
		try:
			allowedConfigIndexes.index(item[0])
		except ValueError:
			continue

		if item[0] == 'debug':
			CURRENT[item[0]] = configParser.getboolean('global', item[0])
		else:
			CURRENT[item[0]] = item[1]

	print "finished parsing global configurations"

#Set argument parsing
argvParser = argparse.ArgumentParser(description='Monitor connection attempts.')

argvParser.add_argument('-f','--socketFile', 
	dest='socketFile', 
	required=False, 
	metavar='file', 
	default=DEFAULT['socket file'],
	help='File to listen for clients(default is '+str(DEFAULT['socket file'])+').')

# TODO:implement inet socket option?

argvParser.add_argument('-c','--conf', 
	required=False, 
	dest='config',
	type=str, 
	metavar='config-file',
	default=DEFAULT['config'],
	help='File holding the configuration.')

#FIXME:implement
argvParser.add_argument('-l','--log', 
	required=False, 
	dest='log',
	type=str, 
	metavar='log-file',
	default=CURRENT['log'],
	help='File to log to.')

# IMPLEMENT
argvParser.add_argument('-m','--max-clients', 
	required=False, 
	dest='maxClients', 
	metavar='clients',
	default=CURRENT['max clients'],
	help='Number of allowed clients(default is '+str(DEFAULT['max clients'])+').')

argvParser.add_argument('-v','--verbose', 
	required=False, 
	dest='verbose',  
	type=str,
	default=CURRENT['verbose'],
	help='More output(debug|info|warn|error|critical) Warn is default.')

argvParser.add_argument('-d','--debug', 
	required=False, 
	dest='debug', 
	action='store_true', 
	default=CURRENT['debug'],
	help='Do not daemonize.')

# TODO:implement
argvParser.add_argument('-q','--quiet', 
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
args = argvParser.parse_args()

#start loggers
log = logging.getLogger('log')

#set file loggers
if args.log:
	print "File logging not implemented yet"
	#sys.exit(0)
	pass

#create console logger and set verbosity level
console = logging.getLogger('console')
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

#daemonize! (or not...)
if args.debug is None or args.debug is not True:
	pid = 0 #kinda useless but more elegant...
	try:
		pid = os.fork()

	except:
		print "Could not fork:"+str(sys.exc_info()[0])
		sys.exit(1)

	if pid != 0:
		console.debug('Main thread forked! Dying...')
		sys.exit(0)

#start queue
myqueue = Queue.Queue()

#start threads
console.debug('Starting sockServer thread')
sockServer_thread = sockServer(args.socketFile, args.maxClients, myqueue)
sockServer_thread.setDaemon(True)
sockServer_thread.start()

console.debug('Starting netMon')
#FIXME:this should be loaded from config
filters = [['tcpSyn-test','tcp[13] = 2'], ['udp-test', 'udp port 53'], ['icmp-test','icmp']]

netMon(myqueue,filters)

#FIXME:should set main thread to do something useful? sockServer? (which blocks?)
while 1:
	try:
		time.sleep(50)
		print "."
	except SystemExit:
		break
	except:
		print "Main (useless) loop end:"+str(sys.exc_info()[0])
		break
console.debug('Main Thread ended.')
sys.exit(0)
