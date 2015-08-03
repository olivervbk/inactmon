#TODO deprecated

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
