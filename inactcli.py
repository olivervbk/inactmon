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

# FIXME:keep message format synced =/
# FIXME:use python logging =/ (just dont remember the details..)
# FIXME:does not exit gracefully on connection term.

DEFAULT_SOCKET_FILE = '/tmp/inactmon.sock'

def exit_gracefully():
	print "exiting gracefully..."
	sys.exit(0)

class notificationManager(threading.Thread):
	__name__='notificationManager'
	server = ''
	port = ''

	def messageParser(self,message):
		output = None
		messages = message.split('\n')
		for m in messages:
			fields = m.split(':')
			auxout = 'unknown'

			if fields[0] == 'tcp':
				if fields[1] == 'syn':
					auxout = 'Connection from '+fields[2]+':'+fields[3]+' on port '+fields[5]
				if fields[2] == 'ack':
					auxout = 'Connected to '+fields[2]+':'+fields[3]+' on port '+fields[4]

			if fields[0] == 'udp':
				auxout = 'Datagram from '+fields[1]+' on port '+fields[2]

			if fields[0] == 'icmp':
				if fields[1] == 'echo':
					auxout = 'Ping request from '+fields[2]+' to '+fields[3]
				if fields[2] == 'reply':
					auxout = 'Ping response to '+fields[3]

			if fields[0] == 'err':
				auxout = 'Error: '+fields[1]

			if output is not None:
				output += '\n'
			else:
				output = ''
			output += auxout
			
		return output
	

	def debug(self,message, level):
		classname = self.__name__
		caller = '('+classname+')'+inspect.stack()[1][3]
		debug(caller, message,level)

	def __init__(self, socketFile):
		gtk.gdk.threads_init() # this makes gtk to allow threads =/
		self.debug("init", "info")
		self.socketFile = socketFile
		threading.Thread.__init__(self)
		self.debug("init done","info")

	def run(self):
		self.debug("run", "info")
		if not pynotify.init('Inactcli'):
			debug("Could not init pynotify", "fatal")
			exit_gracefully()
		self.debug("Pynotify init successful", "info")


		try:
			sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			sock.connect(self.socketFile)
		except socket.error:
			print "Unable to connect! Is the server running?"
			exit_gracefully()
		except:
			print "Unknown Error:",sys.exc_info()[0]
			exit_gracefully()
		

		self.debug("Connected to server", "info")
		while True:
			message = sock.recv(1024)
		
			if not message:
				print "...connection closed"
				break
			message = str(message)
			message = message[:-1] # remove trailing newlines
			print "Message recv:"+message
		
			try:

				notification = pynotify.Notification(
					"Inactcli",
					self.messageParser(message),
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
# parser.add_argument('-p', '--port',
#	dest='port',
#	required=False,
#	metavar='port',
#	default=DEFAULT_PORT,
#	help='Port to connect on server. If a file is specified will create socket at file.')

parser.add_argument('-f', '--socketFile',
	dest='socketFile',
	required=False,
	metavar='file',
	default=DEFAULT_SOCKET_FILE,
	help='Socket File')

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
notMan = notificationManager( args.socketFile)
notMan.setDaemon(True)
notMan.start()

ind = appindicator.Indicator ("inactcli",
	"inactcli-active",
	appindicator.CATEGORY_APPLICATION_STATUS)
ind.set_status (appindicator.STATUS_ACTIVE)
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
