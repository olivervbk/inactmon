#!/usr/bin/python

import ConfigParser

parser = ConfigParser.ConfigParser()
parser.read('inactmon.conf')

print "sections:"+str(parser.sections())

for section in parser.sections():
	print str(section)+':'+str(parser.items(section))
