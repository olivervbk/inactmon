import logging
import copy
import impacket
from impacket import ImpactDecoder

#FIXME:include LEVELS in appLogger class?
LEVELS = {'debug': logging.DEBUG,
          'info': logging.INFO,
          'warn': logging.WARNING,
          'error': logging.ERROR,
          'critical': logging.CRITICAL}

class appLogger:
	# NullHandler: used to make loggers not output(quiet)
	class NullHandler(logging.Handler):
	    def emit(self, record):
	       	pass
	       	
	log = None
	console = None
	
	name = ''
	
	def __init__(self, quiet, verbosity, logfile):
		self.log = logging.getLogger('log')
		self.console = logging.getLogger('console')
		
		#create console logger and set verbosity level
		try:
			level = LEVELS[verbosity]
			self.console.setLevel(level)
		except KeyError:
			print "Verbose option '"+verbosity+"' invalid."
			sys.exit(0)
		
		#check if should be quiet
		if quiet is True:
			nh = self.NullHandler()
			self.console.addHandler(nh)
		else:
			sh = logging.StreamHandler()
			sf = logging.Formatter("%(name)s - %(levelname)s - %(message)s")
			sh.setFormatter(sf)
			self.console.addHandler(sh)
			
		logfile = None #FIXME: remove
		if logfile is None:
			nh = self.NullHandler()
			self.log.addHandler(nh)
		else:
			print "FIXME:log file not implemented yet..."
	
	def newLogger(self,name):
		new = copy.copy(self) #deepcopy gives shit... copy doesn't... no idea why
		new.setName(name)
		return new
		
	def setName(self,name):
		self.name = self.name+'.'+name
		self.log = logging.getLogger('log'+self.name)
		self.console = logging.getLogger('console'+self.name)
		
	def debug(self, message):
		self.log.debug(message)
		self.console.debug(message)
		
	def info(self, message):
		self.log.info(message)
		self.console.info(message)
	
	def warn(self, message):
		self.log.warn(message)
		self.console.warn(message)
		
	def error(self, message):
		self.log.error(message)
		self.console.error(message)
	
	def critical(self, message):
		self.log.critical(message)
		self.console.critical(message)

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


