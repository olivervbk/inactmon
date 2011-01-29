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

DEFAULT_SOCKET_FILE = '/tmp/inactmon.sock'

class appStatus:
	STATUS_OK = 1
	STATUS_DISABLED = 2
	STATUS_ERROR = 3
	STATUS_RECONNECT = 4

	status = STATUS_OK
	def __init__(self,ind, status_item):
		self.ind = ind
		self.status_item = status_item
	def getStatus(self):
		return self.status
	def setStatus(self, status):
		if self.status == self.STATUS_OK:
			if status != self.STATUS_RECONNECT:
				self.status = status
		if self.status == self.STATUS_DISABLED:
			if status != self.STATUS_RECONNECT:
				self.status = status
		if self.status == self.STATUS_ERROR:
			if status != self.STATUS_DISABLED:
				self.status = status
		if self.status == self.STATUS_RECONNECT:
			if status != self.STATUS_DISABLED:
				self.status = status
		self.updateMenu()
	def updateMenu(self):
		if self.status == self.STATUS_OK:
			self.ind.set_status(appindicator.STATUS_ACTIVE)
			self.status_item.set_label("Disable")
		if self.status == self.STATUS_DISABLED:
			#FIXME:set icon here...
			self.ind.set_status(appindicator.STATUS_ATTENTION)
			self.status_item.set_label("Enable")
		if self.status == self.STATUS_ERROR:
			#FIXME:set icon here...
			self.ind.set_status(appindicator.STATUS_ATTENTION)
			self.status_item.set_label("Reconnect")
		if self.status == self.STATUS_RECONNECT:
			#FIXME:set icon here...
			self.ind.set_status(appindicator.STATUS_ATTENTION)
			self.status_item.set_label("Reconnecting...")
			#FIXME:disable button =/ and reenable elsewheres?

def exit_gracefully():
	print "exiting gracefully..."
	gtk.main_quit() #w00t!

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

	def __init__(self, socketFile, statusMan):
		#FIXME:no less obscure place to set this? =/
		gtk.gdk.threads_init() # this makes gtk to allow threads =/
		self.debug("init", "info")

		self.socketFile = socketFile
		self.statusMan = statusMan
		threading.Thread.__init__(self)
		self.debug("init done","info")

	def run(self):
		self.debug("run", "info")
		if not pynotify.init('Inactcli'):
			debug("Could not init pynotify", "fatal")
			exit_gracefully()
		self.debug("Pynotify init successful", "info")

		while(True):
			try:
				sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
				sock.connect(self.socketFile)
			except socket.error:
				self.statusMan.setStatus(appStatus.STATUS_ERROR)
				#FIXME:try to reconnect automatically every x seconds ?
				print "error connecting to server, waiting for reconnect signal"
				while(self.statusMan.getStatus() != appStatus.STATUS_RECONNECT):
					time.sleep(0.2)
				continue
			except:
				print "Unknown Error:",sys.exc_info()[0]
				exit_gracefully()
			break
		
		#if status was reconnecting... 
		self.statusMan.setStatus(appStatus.STATUS_OK)

		self.debug("Connected to server", "info")
		while True:
			message = sock.recv(1024)
		
			if not message:
				print "...connection closed"
				break
			message = str(message)
			message = message[:-1] # remove trailing newlines
			print "Message recv:"+message
		
			if(self.statusMan.getStatus() == appStatus.STATUS_DISABLED):
				print "ignoring message"
				continue

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
		print "...got here?"
		self.run()



def status_button(widget, event=None):
	#FIXME:no way I guess...
	global statusMan
	status = statusMan.getStatus()
	if status == appStatus.STATUS_OK:
		statusMan.setStatus(appStatus.STATUS_DISABLED)
	if status == appStatus.STATUS_DISABLED:
		statusMan.setStatus(appStatus.STATUS_OK)
	if status == appStatus.STATUS_ERROR:
		statusMan.setStatus(appStatus.STATUS_RECONNECT)
	if status == appStatus.STATUS_RECONNECT:
		#do nothing :D
		pass

def destroy_button(widget, event=None):
	print "Quitting via tray..."
	exit_gracefully()

def about_button(widget, event=None):
	print "Status clicked..."


def debug(caller,message,level):
	global args
	if args.verbose:
		print level+':'+str(caller)+':'+str(message)

parser = argparse.ArgumentParser(description='Incoming Netword Activity Client.')

#TODO: perhaps enable inet socket as well
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

ind = appindicator.Indicator ("inactcli",
	"inactcli-active",
	appindicator.CATEGORY_APPLICATION_STATUS)
ind.set_status (appindicator.STATUS_ACTIVE)
ind.set_attention_icon ("inactcli-passive")
# create a menu
menu = gtk.Menu()

status_item = gtk.MenuItem("Disable")
status_item.connect("activate", status_button, "status clicked")
status_item.show()
menu.append(status_item)

about_item = gtk.MenuItem("About")
about_item.connect("activate", about_button,"about")
about_item.show()
menu.append(about_item)

quit_item = gtk.MenuItem("Quit")
quit_item.connect("activate", destroy_button, "file.quit")
quit_item.show()
menu.append(quit_item)

ind.set_menu(menu)

statusMan = appStatus(ind,status_item)

debug("main","Threading notificationManager","info")
notMan = notificationManager( args.socketFile, statusMan)
notMan.setDaemon(True)
notMan.start()

try:
	gtk.main()
except:
	print "main:Terminated! Error:",sys.exc_info()[0]
	#exit_gracefully()
