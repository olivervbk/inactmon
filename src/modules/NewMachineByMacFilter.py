from impacket import ImpactDecoder

import inspect

class NewMachineByMacFilter():
	attributes = None
	myIpAddresses = None
	logger = None

	knownHosts = list()

	def __init__(self, attributes, logger, myIpAddresses):
		self.attributes = attributes
		self.logger = logger
		self.myIpAddresses = myIpAddresses

	def rule(self):
		rule = "arp"
		return rule
		
	def run(self, header, payload):	
		rip = ImpactDecoder.EthDecoder().decode(payload)
		#print rip

		etherType = rip.get_ether_type()
		if etherType != 2054:
			self.logger.warn("doesn't seem to be ARP..")
			return None

		arp = rip.child()
		srcMac = str(arp.as_hrd(arp.get_ar_sha()))
		srcIp = str(arp.as_pro(arp.get_ar_spa()))

		#queriedIp = str(arp.as_pro(arp.get_ar_tpa()))

		if not srcMac in self.knownHosts:
			self.knownHosts.append(srcMac)
			return "A wild host appeared:"+srcMac+"("+srcIp+")"
					
		return None

