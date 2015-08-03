#TODO:use as module

#TODO: support:
from configobj import ConfigObj

#TODO:separate configParser to function? =/
#receives configParser and returns filter?

#Load config file
configParser = ConfigParser.ConfigParser()
#FIXME:try!
try:
	configParser.readfp(open(CURRENT['config']))
except:
	print ("Could not read configuration: %s" % sys.exc_info()[0] )
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
		print (item)
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
			print ("Missing iface information from filter:"+section)
			sys.exit(0)
		except:
			print ("Unknown error reading iface from filter: %s:%s" % section, sys.exc_info()[0] ) 
			sys.exit(0)
		filters[section]['iface'] = iface 
			
		try:
			rule = configParser.get(section, 'rule')
		except ConfigParser.NoOptionError:
			try:
				filterType = configParser.get(section, 'type')

			except ConfigParser.NoOptionError:
				print ("missing rule or type in filter "+section)
				sys.exit(0)

			except:
				print ("Unknown error reading type from filter: "+section+": "+str(sys.exc_info()[0]) )
				sys.exit(1)
			filters[section]['type'] = filterType

		except:
			print ("Unknown error reading rule from filter: "+section+": "+str(sys.exc_info()[0]) )
			sys.exit(1)
		else:
			filters[section]['rule'] = rule
