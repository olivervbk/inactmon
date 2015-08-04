import sys
import logging
import copy

#FIXME:include LEVELS in appLogger class?
LEVELS = {'debug': logging.DEBUG,
          'info': logging.INFO,
          'warn': logging.WARNING,
          'error': logging.ERROR,
          'critical': logging.CRITICAL}


class AppLogger:
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

	def shutdown(self):
		self.log.shutdown()
		self.log = None

		self.console.shutdown()
		self.console = None
	
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
