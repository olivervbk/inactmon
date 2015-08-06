from impacket import ImpactDecoder

import inspect

import time

def dump(obj):
  for name, data in inspect.getmembers(obj):
    if name == '__builtins__':
        continue
    print '%s :' % name, repr(data)

class ScanFilter():
	attributes = None
	myIpAddresses = None
	logger = None

	timestamp = {}
	queries = {}

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
		#print ("op name:"+str(arp.get_op_name(arp.get_ar_op())))

		srcMac = str(arp.as_hrd(arp.get_ar_sha()))
		#print ("src mac:"+srcMac)

		srcIp = str(arp.as_pro(arp.get_ar_spa()))
		#print ("src ip:"+srcIp)

		queriedIp = str(arp.as_pro(arp.get_ar_tpa()))
		#print ("queried ip:"+queriedIp)


		now = time.time()

		last = None
		if srcMac in self.timestamp:
			last = self.timestamp[srcMac]

		# add queried IP to list if exists (remove older if timestamp is suficiently old)
		queriedIps = set()
		if last != None:
			if (now - last) > 5:
				self.queries[srcMac] = queriedIps
			else:
				if not srcMac in self.queries:
					self.queries[srcMac] = queriedIps = set()
				else:
					queriedIps = self.queries[srcMac]	
		else:
			self.queries[srcMac] = queriedIps
		queriedIps.add(queriedIp)

		# save current timestamp
		self.timestamp[srcMac] = now

		# warn only on the first time
		if last != None and (now - last) < 5:
			return None

		if len(queriedIps) > 10:
			return "Possible network scan from: "+srcIp
		
		return None

