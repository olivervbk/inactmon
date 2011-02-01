#!/usr/bin/python

import sys
import signal
import os, os.path
import stat
import time
import datetime

import copy
import ConfigParser
import socket
import threading
import Queue

#FIXME: not really needed anymore
import logging


#FIXME:classes that use the logging functionality should init with the logging base name =/
#TODO:set main thread to do something useful, sockServer?(blocks?)
#TODO:clean up logging system ? =/
#TODO:specials types of filters? (arp-spoofing, et cetera)
#TODO:to be able to remove argparse, must create interface for it =/
#FIXME:do daemonic threads damage non-renewable system resources?(inet sockets?)(pcap resources?)

# Import needed libraries
try:
	import pcapy
except:
	print "Error: could not import pcapy. Please install python-pcapy."
	sys.exit(1)

#FIXME: not really needed HERE anymore
try:
	import impacket
	from impacket import ImpactDecoder
except:
	print "Error: could not import impacket. Please install python-impacket."
	sys.exit(1)

# Import custom lib, must be done after ImpactDecoder and Logging check
import inactlib
from inactlib import appLogger, netMonMessenger

# --- Default Values ---
DEFAULT = {}
DEFAULT['max clients'] = 5
DEFAULT['socket file'] = '/tmp/inactmon.sock'
DEFAULT['verbose'] = 'warn'
DEFAULT['debug'] = False
DEFAULT['config'] = 'inactmon.conf' #FIXME:/etc/inactmon.conf
DEFAULT['log'] = 'inactmon.log'#FIXME:/var/log/inactmon.log

CURRENT = copy.deepcopy(DEFAULT) #damned objects...

# --- Enabled features ---
FEATURES = {}
FEATURES['arguments'] = True
#FEATURES['logging']   = True
FEATURES['netifaces'] = True

try:
	import argparse
except:
	FEATURES['arguments'] = False
	print "Could not import arparse, no alternative implemented yet..."
	print "Please install python-argparser."
	sys.exit(1)

try:
	import netifaces
except:
	FEATURES['netifaces'] = False
	print "Could not import netifaces, no alternative implemented yet..."
	print "Please install python-netifaces."
	sys.exit(1)

# --- Classes ---
# Class that handles clients
class sockServer(threading.Thread):
	#This subclass handles the client comunication in a separate thread. Handles all clients,
	#not just one per instance...
	#Less elegant, though easier than the alternative, multiple inter-thread queues...
	class clientsHandler(threading.Thread):
		queue = None
		clients = []
		logger = None

		def __init__(self, queue, logger):
			self.queue = queue
			self.logger = logger.newLogger('clientsHandler')
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

	def __init__(self, sockFile, maxClients, queue, logger):
		self.sockFile = sockFile
		self.maxClients = int(maxClients)

		self.logger = logger.newLogger('sockServer')

		# run clienthandler thread
		self.cliHandler = self.clientsHandler(queue, self.logger)
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
	# Variable filter class
	class netMonFilter(threading.Thread):
		ipAddresses = None
		myqueue = None
		messenger = None
		logger = None
		name = None
		attributes = None
		iface = None

		def __init__(self,myqueue,messenger,name,attributes, logger):
			#FIXME: args really needed ? =/ just interface is needed... and should be specified by config
			self.attributes = attributes
			self.iface = attributes['iface']
			self.name = name

			self.myqueue = myqueue
			self.messenger = messenger

			self.ipAddresses = self.checkInterface(self.iface)
			self.logger = logger.newLogger(self.name)

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
				exit_gracefully()
			
			#print "%s: net=%s, mask=%s, addrs=%s" % (self.args.interface, cap.getnet(), cap.getmask(), str(self.ipAddresses))

			try:
				self.rule = self.attributes['rule']
			except KeyError:
				self.type = self.attributes['type']
				print "type = "+self.type+" not implemented..."
				return

			
			if self.rule:
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

					message = self.messenger.encode(payload, self.name)
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
				exit_gracefully()

			if 0 == len(ifs):
				print "No interfaces available."
				exit_gracefully()

			if not iface in ifs:
				print "Interface '%s' not found." % (iface)
				exit_gracefully()

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
						exit_gracefully()
			return ipAddresses
	args = None
	ipAddresses = None
	logger = None

	def __init__(self,myqueue,filters, logger):
		self.myqueue = myqueue
		self.filters = filters

		self.logger = logger.newLogger('netMon')

		#FIXME:clean this
		#threading.Thread.__init__(self) #this is not a thread anymore
		self.logger.debug("init:done")
		self.run() #since it is not a thread

	def run(self):
		self.logger.debug("run")
		messenger = netMonMessenger(self.logger)

		self.logger.debug("starting filter engines")
		for name in filters:
			self.logger.debug("reading filter'"+name+"'")
			filter_thread = self.netMonFilter(myqueue, messenger, name, filters[name], self.logger)	
			filter_thread.setDaemon(True)
			filter_thread.start()

		self.logger.debug("done creating engines")


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
#TODO:implementin
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

#TODO:separate configParser to function? =/
#receives configParser and returns filter?

#Load config file
configParser = ConfigParser.ConfigParser()
#FIXME:try!
try:
	configParser.readfp(open(CURRENT['config']))
except:
	print "Could not read configuration:"+str(sys.exc_info()[0])
	sys.exit(0)
	
#FIXME:put somewhere
allowedConfigIndexes = ['socket file', 'log', 'max clients', 'debug', 'verbose']

filters = {}

try:
	configParser.sections().index('global')
except ValueError:
	pass
else:
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

	for section in configParser.sections():
		if section == 'global':
			continue
			
		filters[section] = {}

		try:
			iface = configParser.get(section, 'iface')
		except ConfigParser.NoOptionError:
			print "Missing iface information from filter:"+section
			sys.exit(0)
		except:
			print "Unknown error reading iface from filter: "+section+": "+str(sys.exc_info()[0])
			sys.exit(0)
		filters[section]['iface'] = iface 
			
		try:
			rule = configParser.get(section, 'rule')
		except ConfigParser.NoOptionError:
			try:
				filterType = configParser.get(section, 'type')

			except ConfigParser.NoOptionError:
				print "missing rule or type in filter "+section
				sys.exit(0)

			except:
				print "Unknown error reading type from filter: "+section+": "+str(sys.exc_info()[0])
				sys.exit(1)
			filters[section]['type'] = filterType

		except:
			print "Unknown error reading rule from filter: "+section+": "+str(sys.exc_info()[0])
			sys.exit(1)
		else:
			filters[section]['rule'] = rule
		

#Set argument parsing
argvParser = argparse.ArgumentParser(description='Monitor connection attempts.')

argvParser.add_argument('-f','--socketFile', 
	dest='socketFile', 
	required=False, 
	metavar='file', 
	default=DEFAULT['socket file'], # FIXME:'socket-file' ?
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

argvParser.add_argument('-m','--max-clients', 
	required=False, 
	dest='maxClients', 
	metavar='clients',
	default=CURRENT['max clients'], # FIXME:'max-clients' ?
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

argvParser.add_argument('-q','--quiet', 
	required=False, 
	dest='quiet', 
	action='store_true', 
	help='Show no output(overrides verbosity).', 
	default=False)

#parse args
args = argvParser.parse_args()

#start loggers
logger = appLogger(args.quiet, args.verbose, args.log)


#daemonize! (or not...)
if args.debug is None or args.debug is not True:
	pid = 0 #kinda useless but more elegant...
	try:
		pid = os.fork()

	except:
		print "Could not fork:"+str(sys.exc_info()[0]) #FIXME: should be logger?
		sys.exit(1)

	if pid != 0:
		logger.debug('Main thread forked! Dying...')
		sys.exit(0)

#start queue
myqueue = Queue.Queue()

#start threads
logger.debug('Starting server')
sockServer_thread = sockServer(args.socketFile, args.maxClients, myqueue, logger)
sockServer_thread.setDaemon(True)
sockServer_thread.start()

logger.debug('Starting filters')
netMon(myqueue,filters, logger)

#FIXME:should set main thread to do something useful? sockServer? (which blocks?)
while 1:
	try:
		time.sleep(50)
		print "." #FIXME:remove
	except SystemExit:
		break
	except:
		print "Main (useless) loop end:"+str(sys.exc_info()[0]) #FIXME:as logger?
		break
logger.debug('Main Thread ended.')
sys.exit(0)
