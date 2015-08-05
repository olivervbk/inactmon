from impacket import ImpactDecoder

import inspect

def dump(obj):
  for name, data in inspect.getmembers(obj):
    if name == '__builtins__':
        continue
    print '%s :' % name, repr(data)

class ArpFilter():
	attributes = None
	myIpAddresses = None
	logger = None

	def __init__(self, attributes, logger, myIpAddresses):
		self.attributes = attributes
		self.logger = logger
		self.myIpAddresses = myIpAddresses

	def rule(self):
		rule = "arp and inbound"
		return rule
		
	def run(self, header, payload):	
		self.logger.debug("run")

		self.logger.debug('Setting filter')
		

		rip = ImpactDecoder.EthDecoder().decode(payload)
		print rip

		proto = -1			
		try:
			proto = rip.child().get_ip_p()
		except AttributeError:
			pass

		etherType = rip.get_ether_type()
		if etherType != 2054:
			self.logger.warn("doesnt seem to be ARP..")
			return None

		arp = rip.child()
		print ("op name:"+str(arp.get_op_name(arp.get_ar_op())))

		print ("src mac:"+str(arp.as_hrd(arp.get_ar_sha())))

		print ("src ip:"+str(arp.as_pro(arp.get_ar_spa())))
		print ("queried ip:"+str(arp.as_pro(arp.get_ar_tpa())))
		
		# never send messages
		return None
