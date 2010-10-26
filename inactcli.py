#!/usr/bin/python

import signal
import os, os.path
import pynotify
import sys
import time
import datetime
import socket
import argparse

DEFAULT_PORT = 9123
DEFAULT_SERVER = 'localhost'

parser = argparse.ArgumentParser(description='Incomming Netword Activity Client.')
parser.add_argument('-p', '--port',
	dest='port',
	required=False,
	metavar='port',
	default=DEFAULT_PORT,
	help='Port to connect on server. If a file is specified will create socket at file.')

parser.add_argument('-s', '--server',
	dest='server',
	required=False,
	metavar='server',
	default=DEFAULT_SERVER,
	help='Server host')

parser.add_argument('-v','--verbose', 
	required=False, 
	dest='verbose', 
	action='store_true', 
	help='More output.')

parser.add_argument('-q','--quiet', 
	required=False, 
	dest='verbose', 
	action='store_false', 
	help='Show less output(default)', 
	default=True)




args = parser.parse_args()
verbose = args.verbose

if not pynotify.init( 'Inactcli' ):
	sys.exit(1)

sock = None
for res in socket.getaddrinfo(args.server, int(args.port), socket.AF_UNSPEC, socket.SOCK_STREAM):
    af, socktype, proto, canonname, sa = res
    try:
        sock = socket.socket(af, socktype, proto)
    except socket.error, msg:
        sock = None
        continue
    try:
        sock.connect(sa)
    except socket.error, msg:
        sock.close()
        sock = None
        continue
    break
if sock is None:
    print 'Error: could not open socket'
    sys.exit(1)

while True:
	try:
		message = sock.recv(1024)
		print message
	except:
		print "Error ocurred"
		break
sock.close()
sys.exit(0)

notification = pynotify.Notification(
	"Test", 
	time.strftime("%H:%M:%S", time.localtime()),
	"notification-message-email")
notification.set_urgency(pynotify.URGENCY_NORMAL)
notification.attach_to_widget('self')
#notification.set_timeout(1)

if not notification.show():
	print "Failed to send notification"
	sys.exit(1)


