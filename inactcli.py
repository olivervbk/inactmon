#!/usr/bin/python

import signal
import os, os.path
import threading
import sys
import time
import datetime
import socket

import inspect

import argparse
import pynotify

import gobject
import gtk
import appindicator

DEFAULT_PORT = 9123
DEFAULT_SERVER = 'localhost'

def exit_gracefully():
	print "exiting gracefully..."
	sys.exit(0)

class notificationManager(threading.Thread):
	__name__='notificationManager'
	server = ''
	port = ''

	def debug(self,message, level):
		classname = self.__name__
		caller = '('+classname+')'+inspect.stack()[1][3]
		debug(caller, message,level)

	def __init__(self, server, port):
		gtk.gdk.threads_init() # this makes gtk to allow threads =/
		self.debug("init", "info")
		self.server = server
		self.port = port
		threading.Thread.__init__(self)
		self.debug("init done","info")

	def run(self):
		self.debug("run", "info")
		if not pynotify.init('Inactcli'):
			debug("Could not init pynotify", "fatal")
			exit_gracefully()
		self.debug("Pynotify init successful", "info")
	
		sock = None
		for res in socket.getaddrinfo(self.server, int(self.port), socket.AF_UNSPEC, socket.SOCK_STREAM):
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
			self.debug("Could not open socket. Retrying...", "warn")
			# wait 
			# retry
			self.run()
	
		self.debug("Connected to server", "info")
		while True:
			try:
				message = str(sock.recv(1024))
				message = message[:-1] # remove trailing newlines

				print "Message recv:"+message

				notification = pynotify.Notification(
					"Inactcli",
					message,
					"notification-message-email")
				notification.set_urgency(pynotify.URGENCY_NORMAL)
				notification.set_hint_string("x-canonical-append","")
#				notification.attach_to_widget(self)
				if not notification.show():
					print "Unable to show notification"
			except KeyboardInterrupt:
				print "notMan:Terminated by user"
				sock.close()
				exit_gracefully()
				break

			except:
				print "notMan:Terminated! Error:",sys.exc_info()[0]
				sock.close()
				exit_gracefully()
				break
		sock.close()
		exit_gracefully()



def toggle_status(widget, event=None):
	global ind
	global status_item
	global status
	print "status_clicked:",event
	if ind.get_status() == appindicator.STATUS_ACTIVE:
		ind.set_status(appindicator.STATUS_ATTENTION)
		status_item.set_label("Enable")
	else:
		ind.set_status(appindicator.STATUS_ACTIVE)
		status_item.set_label("Disable")
	print "new label:", status_item.get_label()

def destroy(widget, event=None):
	print "Quitting via tray..."
	exit_gracefully()

def about(widget, event=None):
	print "Status clicked..."
	

def debug(caller,message,level):
	global args
	if args.verbose:
		print level+':'+str(caller)+':'+str(message)


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





# notMan = notificationManager(args.server, args.port)

debug("main","Threading notificationManager","info")
notMan = notificationManager( args.server, args.port)
notMan.setDaemon(True)
notMan.start()

ind = appindicator.Indicator ("inactcli",
	"inactcli-active",
	appindicator.CATEGORY_APPLICATION_STATUS)
ind.set_status (appindicator.STATUS_ACTIVE)
# ind.set_passive_icon("inactcli-passive")
ind.set_attention_icon ("inactcli-passive")
# create a menu
menu = gtk.Menu()

status_item = gtk.MenuItem("Disable")
status_item.connect("activate", toggle_status, "status clicked")
status_item.show()
menu.append(status_item)

about_item = gtk.MenuItem("About")
about_item.connect("activate", about,"about")
about_item.show()
menu.append(about_item)

quit_item = gtk.MenuItem("Quit")
quit_item.connect("activate", destroy, "file.quit")
quit_item.show()
menu.append(quit_item)

ind.set_menu(menu)
try:
	gtk.main()
	#time.sleep(50)
except:
	print "notMan:Terminated! Error:",sys.exc_info()[0]
	exit_gracefully()
