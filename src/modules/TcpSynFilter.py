from impacket import ImpactDecoder

import inspect

import time

def dump(obj):
  for name, data in inspect.getmembers(obj):
    if name == '__builtins__':
        continue
    print '%s :' % name, repr(data)

class TcpSynFilter():
	attributes = None
	myIpAddresses = None
	logger = None

	def __init__(self, attributes, logger, myIpAddresses):
		self.attributes = attributes
		self.logger = logger
		self.myIpAddresses = myIpAddresses

	def rule(self):
		rule = "tcp[tcpflags] == tcp-syn"
		return rule
		
	def run(self, header, payload):	
		rip = ImpactDecoder.EthDecoder().decode(payload)
		print rip

		etherType = rip.get_ether_type()
		print ("ethertype:", etherType)
		
		child = rip.child()
		tcp = child.child()
		
		srcIp = str(child.get_ip_dst())
		dstIp = str(child.get_ip_dst())

		srcPort = str(tcp.get_th_sport())
		dstPort = str(tcp.get_th_dport())
		
		return "Connection attempt on "+dstPort+"(tcp) from "+srcIp+":"+srcPort

