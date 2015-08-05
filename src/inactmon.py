#!/usr/bin/python

import sys
import signal
import os, os.path
import stat
import time
import datetime

import traceback
import argparse
import copy
import socket
from threading import Thread
import imp
import json

import pcapy
import impacket
import netifaces

# Import custom lib, must be done after ImpactDecoder and Logging check
import inactlib
from inactlib import AppLogger

if sys.version_info >= (2,0):
	from Queue import Queue
else:
	print ("Python version unsupported: %s" % sys.version_info)
	sys.exit(1)


#FIXME:classes that use the logging functionality should init with the logging base name =/
#TODO:set main thread to do something useful, sockServer?(blocks?)
#TODO:clean up logging system ? =/
#TODO:specials types of filters? (arp-spoofing, et cetera)
#TODO:to be able to remove argparse, must create interface for it =/
#FIXME:do daemonic threads damage non-renewable system resources?(inet sockets?)(pcap resources?)


# --- Default Values ---
DEFAULT = {}
DEFAULT['max clients'] = 5
DEFAULT['socket file'] = '/tmp/inactmon.sock'
DEFAULT['verbose'] = 'warn'
DEFAULT['debug'] = False
DEFAULT['config'] = 'inactmon.conf' #FIXME:/etc/inactmon.conf
DEFAULT['log'] = 'inactmon.log'#FIXME:/var/log/inactmon.log
DEFAULT['interface'] = "eth0"

CURRENT = copy.deepcopy(DEFAULT) #damned objects...

logger = None

import ConfigParser

# --- Classes ---
# Class that handles clients
class sockServer(Thread):
	#This subclass handles the client comunication in a separate thread. Handles all clients,
	#not just one per instance...
	#Less elegant, though easier than the alternative, multiple inter-thread queues...
	class clientsHandler(Thread):
		queue = None
		clients = []
		logger = None

		def __init__(self, queue, logger):
			self.queue = queue
			self.logger = logger.newLogger('clientsHandler')
			Thread.__init__(self)
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

		Thread.__init__(self)

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
			self.logger.error("os.remove exception:"+sys.exc_info()[0] )
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
				self.logger.error("socket loop exception:"+str(sys.exc_info()[0]))
				break

		#The following will probably never run since sock.accept() blocks and this thread is 'killed' on exit
		self.sock.close()
		exit_gracefully()

# Class that handles filters	
class netMon:
	args = None
	ipAddresses = None
	logger = None
	myqueue = None

	def __init__(self,myqueue,filters, logger):
		self.myqueue = myqueue
		self.filters = filters

		self.logger = logger.newLogger('netMon')

		#FIXME:clean this
		#threading.Thread.__init__(self) #this is not a thread anymore
		self.logger.debug("init:done")
		self.run() #since it is not a thread

	def checkInterface(self, iface):
		# check if there are interfaces available with pcapy
		try:
			ifs = pcapy.findalldevs()
		except pcapy.PcapError:
			self.logger.error("Unable to get interfaces. Are you running as root?")
			exit_gracefully()

		if 0 == len(ifs):
			self.logger.error("No interfaces available.")
			exit_gracefully()

		if not iface in ifs:
			self.logger.error("Interface '%s' not found." % (iface))
			exit_gracefully()

		ipAddresses = [] 
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
					self.logger.error("Interface '%s' is down." % (iface))
					exit_gracefully()
		return ipAddresses

	def run(self):
		self.logger.debug("run")

		iface = CURRENT['interface'] 
		ipAddresses = self.checkInterface(iface)

		self.logger.debug("starting filter engines")
		for name in self.filters:
			self.logger.debug("creating filter:"+name)

			#create logger
			childLogger = self.logger.newLogger(name)

			## this would be used if the class were defined in here...
			#clazz = globals()[name]
			module = loadModule(name)
			clazz = getattr(module, name)
	
			instance = None		
			# TODO load dinamically
			properties = {}
			try:
				instance = clazz( properties, childLogger, ipAddresses)
			except:
				self.logger.error("Unable to instantiate filter '"+name+"'")
				traceback.print_exc()
				continue

			# Arguments here are:
			#   device
			#   snaplen (maximum number of bytes to capture _per_packet_)
			#   promiscious mode (1 for true)
			#   timeout (in milliseconds)
			snaplen = 1500

			self.logger.debug("Opening interface:"+iface+" snaplen:"+str(snaplen))
			cap = pcapy.open_live(iface,snaplen, 0, 0)

			if pcapy.DLT_EN10MB != cap.datalink():
				self.logger.error ("Interface is not ethernet based. Quitting...")
				exit_gracefully()

			self.logger.debug("%s: net=%s, mask=%s, addrs=%s" % (iface, cap.getnet(), cap.getmask(), str(ipAddresses)) )

			# configure rule from filter
			rule = instance.rule()
			try:
				cap.setfilter( rule )				
			except:
				self.logger.error("Unable to set rule '"+rule+"' for filter '"+name+"'")
				traceback.print_exc()
				continue

			# create thread that monitors capture
			def workerThread(instance, interface, queue):
				lastMessageTimestamp = time.time()
				while True:
					header = payload = None
					try:
						#this may block
						(header, payload) = interface.next()
					except:
						self.logger.error("cap.next() exception:"+str(sys.exc_info()[0]))
						traceback.print_exc()
						continue

					try:
						message = instance.run(header, payload)
						if message == None:
							continue

						filterName = str(instance.__class__.__name__)

						# TODO configurable time
						# TODO improve logic using quantity of messages/time instead of just a time limit
						if time.time() - lastMessageTimestamp > 5:
							lastMessageTimestamp = time.time()

							data = {}
							data['filter'] = filterName
							data['message'] = message
							data['timestamp'] = time.time()
							json_data = json.dumps(data)

							queue.put(json_data)
						else:
							self.logger.debug("ignoring too many messages from: "+filterName)
					except:
						self.logger.error("filter exception:"+str(sys.exc_info()[0]))
						traceback.print_exc()
						continue	
						

			self.logger.debug("Starting filter in new thread'"+name+"'")
			thread = Thread(target = workerThread, args=(instance, cap, self.myqueue))
			thread.setDaemon(True)
			thread.start()

		self.logger.debug("Done creating filter engines")


def signal_handler(signal_recv, frame):
	if signal_recv == signal.SIGINT:
		exit_gracefully()

	if signal_recv == signal.SIGHUP:
		reload_config()

def exit_gracefully(code=0):
	print ("\nexiting...")

#FIXME:socket.accept and pcapy.next are blocking... AND signals are only treated in the main thread..,
#	this could lead to problems when dealing with non reusable system resources(like inet sockets =/)
#	With daemonic threads they are killed automatically and silently... I guess...

#	Alternatives:
#	signal.alarm() # does nothing =/ must implement with alarm.pause? but socket.accept is blocking...
#	os.kill(os.getpid(), signal.SIGKILL) # kills all threads
#	os.kill(os.getpid(), signal.SIGTERM) # terminates all threads
#	os._exit(0) # kills all threads
#	sys.exit(0) # does only exit current thread(main)

	sys.exit(code)

def reload_config():
#TODO:implement
	print ("\nreload config")

def loadModule(name, path=None):
	if path == None:
		pathDir = os.path.dirname(os.path.realpath(__file__))
		path = pathDir+"/modules/"+name+".py"
	return imp.load_source(name, path)

	fp, pathname, description = imp.find_module(name, path)

	try:
		return imp.load_module(name, fp, pathname, description)
		
	finally:
		# Since we may exit via an exception, close fp explicitly.
		if fp:
			fp.close()

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

argvParser.add_argument('-i','--interface', 
	required=False, 
	dest='interface',  
	type=str,
	default=CURRENT['interface'],
	help="Defines the interface to listen on (must be pcap compatible). Default is "+str(DEFAULT['interface']))

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

CURRENT['interface'] = args.interface

#start loggers
logger = AppLogger.AppLogger(args.quiet, args.verbose, args.log)


#daemonize! (or not...)
if args.debug is None or args.debug is not True:
	pid = 0 #kinda useless but more elegant...
	try:
		pid = os.fork()

	except:
		logger.error("Could not fork:"+str(sys.exc_info()[0]) ) #FIXME: should be logger?
		sys.exit(1)

	if pid != 0:
		logger.debug('Main thread forked! Dying...')
		sys.exit(0)

#start queue
myqueue = Queue()

#start threads
logger.debug('Starting server')
sockServer_thread = sockServer(args.socketFile, args.maxClients, myqueue, logger)
sockServer_thread.setDaemon(True)
sockServer_thread.start()

logger.debug('Starting filters')

filters = ["IcmpFilter", "ScanFilter", "TcpSynFilter" ]#"ArpFilter"]

netMon(myqueue,filters, logger)

#FIXME:should set main thread to do something useful? sockServer? (which blocks?)
while 1:
	try:
		time.sleep(50)
	except SystemExit:
		break
	except:
		break
logger.debug('Main Thread ended.')
sys.exit(0)
