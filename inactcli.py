#!/usr/bin/python

import signal
import os, os.path
import threading
import sys
import time
import datetime
import socket

import inspect

# FIXME:aboutdialog in appindicator crashes on close
# FIXME:keep message format synced =/
# FIXME:use python logging =/ (just dont remember the details..) and remove inspect

FEATURES = {}
FEATURES['notify'] = True
FEATURES['interface'] = None
FEATURES['tray'] = None

DEFAULT_SOCKET_FILE = '/tmp/inactmon.sock'

try:
	import argparse
except:
	print "Could not import argparse. Please install python-argparse."
	sys.exit(1)

try:
	import pynotify
except:
	print "Could not import pynotify. Please install python-pynotify."
	FEATURES['notify'] = False
	sys.exit(1)

try:
	import appindicator2
except:
	print "Could not import appindicator. Trying fallback..."
	try:
		import egg.trayicon
	except:
		print "Could not import eggtrayicon. Trying fallback..."
		FEATURES['tray'] = "gtk"
	else:
		FEATURES['tray'] = "egg"
else:
	FEATURES['tray'] = "indicator"

try:
	import gobject
	import gtk
except:
	print "Could not load GTK. Trying fallback..."
	FEATURES['interface'] = False
	FEATURES['tray'] = False
else:
	if FEATURES['tray'] is None:
		FEATURES['tray'] = "gtk"
	FEATURES['interface'] = "gtk"

class appStatus:
	STATUS_OK = 1
	STATUS_DISABLED = 2
	STATUS_ERROR = 3
	STATUS_RECONNECT = 4

	status = STATUS_OK
	tray = None

	def __init__(self,tray):
		self.tray = tray
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
			self.tray.setIcon(icon = None, status = "active")
			self.tray.setActionLabel(label = "Disable")
		if self.status == self.STATUS_DISABLED:
			#FIXME:set icon here...
			self.tray.setIcon(icon = None, status = "attention")
			self.tray.setActionLabel(label = "Enable")
		if self.status == self.STATUS_ERROR:
			#FIXME:set icon here...
			self.tray.setIcon(icon = None, status = "attention")
			self.tray.setActionLabel(label = "Reconnect")
		if self.status == self.STATUS_RECONNECT:
			#FIXME:set icon here...
			self.tray.setIcon(icon = None, status = "attention")
			self.tray.setActionLabel(label = "Reconnecting...")
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

#FIXME:this must go
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

if FEATURES['interface'] == "gtk":
	class aboutDialog:
		def __init__(self):
			aboutdialog = gtk.AboutDialog()
			aboutdialog.set_name("Inactmon-cli")
			aboutdialog.set_version("1.0")
			aboutdialog.set_copyright("Don't redistribute! :P")
			aboutdialog.set_comments("Shows notifications about incomming activity based on pcap rules.")
			aboutdialog.set_authors(["Oliver Kuster"])
			aboutdialog.set_logo(gtk.gdk.pixbuf_new_from_file_at_size("eye-version3-active.svg",100,100))
		
			aboutdialog.run()
			aboutdialog.destroy()
else:
	class aboutDialog:
		def __init__(self):
			print "interface not specified..."

if FEATURES['tray'] == 'indicator':
	class trayIcon:
		ind = None
		status_item = None
		def __init__(self):
			self.ind = ind = appindicator.Indicator ("inactcli",
				"inactcli-active",
				appindicator.CATEGORY_APPLICATION_STATUS)
			ind.set_status (appindicator.STATUS_ACTIVE)
			ind.set_attention_icon ("inactcli-passive")
			# create a menu
			menu = gtk.Menu()

			self.status_item = status_item = gtk.MenuItem("Disable")
			status_item.connect("activate", self.status_button, "status clicked")
			menu.append(status_item)

			about_item = gtk.MenuItem("About")
			about_item.connect("activate", self.about_button,"about")
			menu.append(about_item)

			quit_item = gtk.MenuItem("Quit")
			quit_item.connect("activate", self.destroy_button, "file.quit")
			menu.append(quit_item)
			menu.show_all()

			ind.set_menu(menu)
		
		def setIcon(self, status, icon):
			if status == "active":
				status = appindicator.STATUS_ACTIVE
			elif status == "attention":
				status = appindicator.STATUS_ATTENTION
			else:
				print "Unknown status: "+status
				return
			self.ind.set_status(status)

			if icon is not None:
				self.ind.set_attention_icon(icon)

		def setActionLabel(self,label):
			self.status_item.set_label(label)

		def status_button(self,widget, event=None):
			#FIXME:statusMan is actually parent...
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

		def destroy_button(self,widget, event=None):
			print "Quitting via tray..."
			exit_gracefully()

		def about_button(self,widget, event=None):
			aboutDialog()

elif FEATURES['tray'] == "egg":
	class trayIcon:
		def __init__(self):
			self.tray = egg.trayicon.TrayIcon("inactcli")

			eventbox = gtk.EventBox()
			image = gtk.Image()
			image.set_from_file("eye-version3-active.svg")
		
			eventbox.connect("button-press-event", self.icon_clicked)
		
			eventbox.add(image)
			self.tray.add(eventbox)
			self.tray.show_all()

			self.menu = menu = gtk.Menu()
			self.menuitem_status = menuitem_status = gtk.MenuItem("Disable")
			menuitem_about = gtk.MenuItem("About")
			menuitem_exit = gtk.MenuItem("Exit")
			menu.append(menuitem_status)
			menu.append(menuitem_about)
			menu.append(menuitem_exit)
			menuitem_about.connect("activate", self.aboutdialog)
			menuitem_status.connect("activate", self.status_button)
			#FIXME:exit_gracefully() >_>
			menuitem_exit.connect("activate", lambda w: gtk.main_quit())
			menu.show_all()
		    
		def icon_clicked(self, widget, event):
			if event.button == 1:
				self.menu.popup(None, None, None, event.button, event.time, self.tray)
		    
		def aboutdialog(self, widget):
			aboutDialog()

		def status_button(self,widget, event=None):
			#FIXME:statusMan is actually parent...
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

		def setIcon(self, status, icon):
			#TODO:implement
			pass
		def setActionLabel(self,label):
			self.menuitem_status.set_label(label)
		
elif FEATURES['tray'] == "gtk":
	class trayIcon:
		def __init__(self):
			print "class trayIcon for gtk is not implemented yet..."
			#TODO:implement
		def setIcon(self, status, icon):
			#TODO:implement
			pass
		def setActionLabel(self,label):
			#TODO:implement
			pass

else:
	class trayIcon:
		def __init__(self):
			print "class trayIcon for no interface loaded..."
		def setIcon(self, status, icon):
			#TODO:implement
			pass
		def setActionLabel(self,label):
			#TODO:implement
			print "New label:"+label

tray = trayIcon()

statusMan = appStatus(tray)

debug("main","Threading notificationManager","info")
notMan = notificationManager( args.socketFile, statusMan)
notMan.setDaemon(True)
notMan.start()

try:
	gtk.main()
except:
	print "main:Terminated! Error:",sys.exc_info()[0]
	#exit_gracefully()
