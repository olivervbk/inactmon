from impacket import ImpactDecoder

class IcmpFilter():
	attributes = None
	myIpAddresses = None
	logger = None

	def __init__(self, attributes, logger, myIpAddresses):
		self.attributes = attributes
		self.logger = logger
		self.myIpAddresses = myIpAddresses

	def rule(self):
		rule = "icmp[icmptype] == icmp-echo"
		#rule = "icmp-echo"
		#rule = "icmp"
		return rule

		
	def run(self, header, payload):
		rip = ImpactDecoder.EthDecoder().decode(payload)
		#print rip

		proto = -1			
		try:
			proto = rip.child().get_ip_p()
		except AttributeError:
			pass


		# NOT ICMP
		if proto != 1:
			self.logger.warn('got packet that was not ICMP?!')
			return None

		icmpType = rip.child().child().get_icmp_type()
		if(icmpType == rip.child().child().ICMP_ECHOREPLY):
			self.logger.warn('got icmp ECHOREPLY?!')
			return None

		#if(icmpType == rip.child().child().ICMP_ECHO):
		#	status = 'echo'

		dstAddr = rip.child().get_ip_dst()
		srcAddr = rip.child().get_ip_src()

		message = 'icmp echo request from '+srcAddr+' to '+dstAddr

		self.logger.debug("msg rcvd: "+str(message))
		return message
