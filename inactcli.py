#!/usr/bin/python

import signal
import os, os.path
import pynotify
import sys
import time
import datetime
import socket
import argparse

import gobject
import gtk
import appindicator

DEFAULT_PORT = 9123
DEFAULT_SERVER = 'localhost'

def exit_gracefully():
	print "exiting..."
	sys.exit(0)

def notificationManager():
	if not pynotify.init( 'Inactcli' ):
		debug("Could not start pynotify")
		exit_gracefully()

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
		print "Could not open socket"
		exit_gracefully()

	debug("Connected to server")
	while True:
		try:
			message = sock.recv(1024)
			debug("Message recv:"+str(message))
			notification = pynotify.Notification(
				"Inactcli",
				message,
				"notification-message-email")
			notification.set_urgency(pynotify.URGENCY_NORMAL)
			notification.set_hint_string("x-canonical-append","")
#			notification.attach_to_widget(self)
			if not notification.show():
				print "Unable to show notification"
		except:
			print "Terminated! Error:",sys.exc_info()[0]
			break
	sock.close()

parser = argparse.ArgumentParser(description='Incoming Netword Activity Client.')
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

exit_gracefully()

def status_clicked(widget, event=None):
	global ind
	global status_item
	global menu
	print "status_clicked:",event
	print "old label:",status_item.get_child().get_label()
	if ind.get_status() == appindicator.STATUS_ACTIVE:
		print "changed to attention"
		ind.set_status(appindicator.STATUS_ATTENTION)
		status_item.get_child().set_label("Change To Act")
	else:
		print "changed to active"
		ind.set_status(appindicator.STATUS_ACTIVE)
		status_item.get_child().set_label("Change To Att")
#	status_item.realize()
#	status_item.map()
#	status_item.queue_draw()
	menu.queue_draw()
	print "new label:", status_item.get_child().get_label()

def destroy(widget, event=None):
	print "destroyed"
	sys.exit(0)

if __name__ == "__main__":
	ind = appindicator.Indicator ("example-simple-client",
			"indicator-messages",
			appindicator.CATEGORY_APPLICATION_STATUS)
	ind.set_status (appindicator.STATUS_ACTIVE)
	ind.set_attention_icon ("new-messages-red")
  	# create a menu
   	menu = gtk.Menu()

	status_item = gtk.MenuItem("Porra")
	status_item.connect("activate", status_clicked, "status clicked")
	status_item.show()
	menu.append(status_item)

	quit_item = gtk.MenuItem("Quit")
	quit_item.connect("activate", destroy, "file.quit")
	quit_item.show()
	menu.append(quit_item)

	status_item.get_child().set_label("Change To Att")

  	ind.set_menu(menu)

    	gtk.main()
