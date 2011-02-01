#!/usr/bin/python

import signal
import os, os.path
import threading
import sys
import time
import datetime
import socket
import logging

import inactlib
from inactlib import appLogger, netMonMessenger


# FIXME:no need for complicated status button functions
# FIXME:aboutdialog in appindicator crashes on close
# FIXME:gtk trayicon shows menu on left click =/
# TODO: implement icon changes, all of them =/
# TODO: set version variables and improve about dialog
# TODO: set icon variables
# TODO: outsource menu creation for gtk
# TODO: keep message format synced =/
# TODO: improve logging

FEATURES = {}
FEATURES['notify'] = True
FEATURES['interface'] = None
FEATURES['tray'] = None

DEFAULT_SOCKET_FILE = '/tmp/inactmon.sock'
DEFAULT_VERBOSE_LEVEL = 'warn'

ICONS = {}
ICONS['active'] = {}
ICONS['active']['filename'] = "eye-version3-active.svg"
ICONS['active']['name'] = "inactcli-active"
ICONS['disabled']={}
ICONS['disabled']['filename'] = "eye-version3-passive.svg"
ICONS['disabled']['name'] = "inactcli-passive"
ICONS['error']={}
ICONS['error']['filename'] = "eye-version3-attention.svg"
ICONS['error']['name'] = "inactcli-attention"

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
	import appindicator
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

	def __init__(self):
		pass
	def setTray(self,tray):
		self.tray = tray

	def getStatus(self):
		return self.status

	def updateStatusByButton(self):
		if self.status == appStatus.STATUS_OK:
			self.setStatus(appStatus.STATUS_DISABLED)
		elif self.status == appStatus.STATUS_DISABLED:
			self.setStatus(appStatus.STATUS_OK)
		elif self.status == appStatus.STATUS_ERROR:
			self.setStatus(appStatus.STATUS_RECONNECT)
		elif self.status == appStatus.STATUS_RECONNECT:
			#do nothing :D
			pass

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
			self.tray.setIcon(icon = "active", status = "active")
			self.tray.setActionLabel(label = "Disable")
		if self.status == self.STATUS_DISABLED:
			#FIXME:set icon here...
			self.tray.setIcon(icon = "disabled", status = "attention")
			self.tray.setActionLabel(label = "Enable")
		if self.status == self.STATUS_ERROR:
			#FIXME:set icon here...
			self.tray.setIcon(icon = "error", status = "attention")
			self.tray.setActionLabel(label = "Reconnect")
		if self.status == self.STATUS_RECONNECT:
			#FIXME:set icon here...
			self.tray.setIcon(icon = None, status = "attention")
			self.tray.setActionLabel(label = "Reconnecting...")
			#FIXME:disable button =/ and reenable elsewheres?

def exit_gracefully():
	print "exiting gracefully..."
	gtk.main_quit() #w00t!

if FEATURES['interface'] == "gtk":
	class appNotifier:
		def __init__(self):
			if not pynotify.init('Inactcli'):
				print "error initializing pynotify."
				exit_gracefully()
		def showMessage(self,message):
			notification = pynotify.Notification(
				"Inactcli",
				message,
				"notification-message-email")
			notification.set_urgency(pynotify.URGENCY_NORMAL)
			notification.set_hint_string("x-canonical-append","")
#			notification.attach_to_widget(self)
			if not notification.show():
				print "Unable to show notification"
else:
	class appNotifier:
		def __init__(self):
			print "notifier init: no interface. Falling back to terminal."
		def showMessage(self,message):
			print message

class notificationManager(threading.Thread):
	server = ''
	port = ''
	notifier = None

	def __init__(self, socketFile, statusMan, logger):
		self.logger = logger.newLogger('notMan')
		self.logger.debug("init")
	
		self.socketFile = socketFile
		self.statusMan = statusMan
	
		self.notifier = appNotifier()
		
		self.parser = netMonMessenger(logger)

		threading.Thread.__init__(self)
		self.logger.debug("init done")

	def run(self):
		self.logger.debug("run")

		while(True):
			try:
				sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
				sock.connect(self.socketFile)
			except socket.error:
				self.statusMan.setStatus(appStatus.STATUS_ERROR)
				#FIXME:try to reconnect automatically every x seconds ?
				print "error connecting to server, waiting for reconnect signal"
				while(self.statusMan.getStatus() != appStatus.STATUS_RECONNECT):
					time.sleep(0.2) #FIXME: waits for status updates...
				continue
			except:
				print "Unknown Error:",sys.exc_info()[0]
				exit_gracefully()
			break
		
		#if status was reconnecting... 
		self.statusMan.setStatus(appStatus.STATUS_OK)

		self.logger.debug("Connected to server")
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
				self.notifier.showMessage(self.parser.decode(message))
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
	type=str,
	default=DEFAULT_VERBOSE_LEVEL,
	help='More output(debug|info|warn|error|critical) Warn is default.')

parser.add_argument('-q','--quiet', 
	required=False, 
	dest='quiet', 
	action='store_true',
	help='Show no output(overrides verbosity)', 
	default=False)




args = parser.parse_args()

logger = appLogger(args.quiet, args.verbose, None)

if FEATURES['interface'] == "gtk":
	def aboutDialog(widget, event=None):
#			self.logger = logger.newLogger('aboutDialog-gtk')
			
#			self.logger.debug('init')
			aboutdialog = gtk.AboutDialog()
			
			aboutdialog.set_name("Inactmon-cli")
			aboutdialog.set_version("1.0")
			aboutdialog.set_copyright("Don't redistribute! :P")
			aboutdialog.set_comments("Shows notifications about incomming activity based on pcap rules.")
			aboutdialog.set_authors(["Oliver Kuster"])
			aboutdialog.set_logo(gtk.gdk.pixbuf_new_from_file_at_size("eye-version3-active.svg",100,100))
#			self.logger.debug('done setting values, running')
			
		
			aboutdialog.run()
#			self.logger.debug('done running, destroying')
			
			aboutdialog.destroy()
#			self.logger.debug('done')
else:
	class aboutDialog:
		def __init__(self, logger):
			self.logger = logger.newLogger('aboutDialog-none')
			self.logger.debug('init')
			print "interface not specified..."
			self.logger.debug('done')

if FEATURES['tray'] == 'indicator':
	class trayIcon:
		ind = None
		status_item = None
		def __init__(self, statusMan,logger):	
			self.logger = logger.newLogger('trayIcon-indicator')
			
			self.statusMan = statusMan
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
			about_item.connect("activate", aboutDialog,"about")
			menu.append(about_item)

			quit_item = gtk.MenuItem("Quit")
			quit_item.connect("activate", self.destroy_button, "file.quit")
			menu.append(quit_item)
			menu.show_all()

			ind.set_menu(menu)
		
		def setIcon(self, status, icon):
			global ICONS

			if icon is not None:
				self.ind.set_attention_icon(ICONS[icon]['name'])

			if status == "active":
				status = appindicator.STATUS_ACTIVE
			elif status == "attention":
				status = appindicator.STATUS_ATTENTION
			else:
				print "Unknown status: "+status
				return
			self.ind.set_status(status)

		def setActionLabel(self,label):
			self.status_item.set_label(label)

		def status_button(self,widget, event=None):
			self.statusMan.updateStatusByButton()

		def destroy_button(self,widget, event=None):
			print "Quitting via tray..."
			exit_gracefully()

		def about_button(self,widget, event=None):
			try:
				aboutDialog(self.logger)
			except:
				print "error showing about dialog:",sys.exc_info()[0]
			else:
				print "about-dialog:done"

elif FEATURES['tray'] == "egg":
	class trayIcon:
		def __init__(self, statusMan, logger):
			self.logger = logger.newLogger('trayIcon-egg')
			self.statusMan = statusMan
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
			menuitem_exit.connect("activate", self.destroy_button)
			menu.show_all()
		    
		def icon_clicked(self, widget, event):
			if event.button == 1:
				self.menu.popup(None, None, None, event.button, event.time, self.tray)
		    
		def aboutdialog(self, widget):
			aboutDialog(self.logger)

		def status_button(self,widget, event=None):
			self.statusMan.updateStatusByButton()

		def destroy_button(self,widget,event=None):
			exit_gracefully()

		def setIcon(self, status, icon):
			#TODO:implement
			pass
		def setActionLabel(self,label):
			self.menuitem_status.set_label(label)
		
elif FEATURES['tray'] == "gtk":
	class trayIcon(gtk.StatusIcon):
		def __init__(self, statusMan, logger):
			self.logger = logger.newLogger('trayIcon-gtk')
			
			self.statusMan = statusMan
			gtk.StatusIcon.__init__(self)
			
			self.set_from_file("eye-version3-active.svg")
			self.set_tooltip('Inactcli')
			self.set_visible(True)

			self.menu = menu = gtk.Menu()

			self.status_item = status_item = gtk.MenuItem("Disable")
			status_item.connect("activate", self.status_button, "status clicked")
			menu.append(status_item)

			about_item = gtk.MenuItem("About")
			about_item.connect("activate", self.aboutdialog,"about")
			menu.append(about_item)

			quit_item = gtk.MenuItem("Quit")
			quit_item.connect("activate", self.destroy_button, "file.quit")
			menu.append(quit_item)
			menu.show_all()

			self.connect('popup-menu', self.icon_clicked)

		def icon_clicked(self, status, button, time):
			self.menu.popup(None, None, None, button, time)

		def aboutdialog(self, widget, event=None):
			aboutDialog(self.logger)

		def status_button(self,widget, event=None):
			self.statusMan.updateStatusByButton()

		def destroy_button(self,widget,event=None):
			exit_gracefully()

		def setIcon(self, status, icon):
			#TODO:implement
			pass
		def setActionLabel(self,label):
			self.status_item.set_label(label)

else:
	class trayIcon:
		def __init__(self,statusMan, logger):
			self.logger = logger.newLogger('trayIcon-none')
			
			self.statusMan = statusMan
			print "class trayIcon for no interface loaded..."
		def setIcon(self, status, icon):
			#TODO:implement
			pass
		def setActionLabel(self,label):
			#TODO:implement
			print "New label:"+label



#FIXME:Fruit salad..
statusMan = appStatus()
tray = trayIcon(statusMan, logger)
statusMan.setTray(tray)

if FEATURES['interface'] == "gtk":
	gtk.gdk.threads_init() # this makes gtk to allow threads =/

logger.info("Threading notificationManager")
notMan = notificationManager( args.socketFile, statusMan, logger)
notMan.setDaemon(True)
notMan.start()

try:
	if FEATURES['interface'] == "gtk":
		gtk.main()
	else:
		#just sleep?
		while(True):
			time.sleep(50)
			#print "."
except:
	print "main:Terminated! Error:",sys.exc_info()[0]
	#exit_gracefully()
