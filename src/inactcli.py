#!/usr/bin/python

import signal
import os, os.path
import threading
import sys
import time
import datetime
import socket
#import logging
import copy
import traceback
import json

#import inactlib
#from inactlib import appLogger, netMonMessenger

from inactlib import AppLogger

# FIXME:no need for complicated status button functions
# FIXME:gtk trayicon shows menu on left click =/
# TODO: implement icon changes, all of them =/
# TODO: set version variables and improve about dialog
# TODO: set icon variables
# TODO: outsource menu creation for gtk
# TODO: keep message format synced =/
# TODO: improve logging

DEFAULT_SOCKET_FILE = '/tmp/inactmon.sock'
DEFAULT_VERBOSE_LEVEL = 'debug'

ICONS = {}
ICONS['active'] = {}
ICONS['active']['filename'] = "../images/eye-version3-active.svg"
ICONS['active']['name'] = "inactcli-active"
ICONS['disabled']={}
ICONS['disabled']['filename'] = "../images/eye-version3-passive.svg"
ICONS['disabled']['name'] = "inactcli-passive"
ICONS['error']={}
ICONS['error']['filename'] = "../images/eye-version3-attention.svg"
ICONS['error']['name'] = "inactcli-attention"

import argparse

# pynotify->gi.repository.Notify
#if sys.version_info >= (3, 0):
	
if sys.version_info >= (2,0):
	from gi.repository import Notify
#	import pynotify
else:
	print ("Python version unknown: %s" % sys.version_info)
	sys.exit(1)

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

class notificationManager(threading.Thread):
	server = ''
	port = ''
	notifier = None

	def __init__(self, socketFile, statusMan, logger, notifier):
		self.logger = logger
		self.logger.debug("init")
	
		self.socketFile = socketFile
		self.statusMan = statusMan
	
		self.notifier = notifier

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
				logger.warn("error connecting to server, waiting for reconnect signal")
				while(self.statusMan.getStatus() != appStatus.STATUS_RECONNECT):
					time.sleep(0.2) #FIXME: waits for status updates...
				continue
			except:
				logger.error( "Unknown Error:",sys.exc_info()[0])
				exit_gracefully()
			break
		
		#if status was reconnecting... 
		self.statusMan.setStatus(appStatus.STATUS_OK)

		self.logger.debug("Connected to server")
		while True:
			try:
				jsonData = sock.recv(1024)
		
				if not jsonData:
					self.logger.debug( "...connection closed")
					break
				self.logger.debug( "Message recv:"+str(jsonData))

				data = json.loads(jsonData)
				message = data['message']
				filterName = data['filter']
		
				if(self.statusMan.getStatus() == appStatus.STATUS_DISABLED):
					logger.debug( "ignoring message")
					continue

				self.notifier.showMessage(filterName, message)
			except KeyboardInterrupt:
				self.logger.warn( "notMan:Terminated by user")
				sock.close()
				exit_gracefully()
				break

			except:
				self.logger.error("notMan:Terminated! Error:"+str(sys.exc_info()[0]))
				traceback.print_exc()
				break
		print ("...got here?")
		self.run()

def exit_gracefully():
	logger.debug( "exiting gracefully...")
	Gtk.main_quit() #w00t!

def absolutePath():
	pathDir = os.path.dirname(os.path.realpath(__file__))
	return pathDir

#__main__:

parser = argparse.ArgumentParser(description='Incoming Network Activity Client.')

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

parser.add_argument('-g','--gtk', 
	required=False, 
	dest='interface', 
	action='store_const',
	const='gtk',
	help='Use gtk interface.', 
	default='gtk')

parser.add_argument('-t','--text', 
	required=False, 
	dest='interface', 
	action='store_const',
	const='text',
	help='Use text interface.', 
	default='gtk')

args = parser.parse_args()

logger = AppLogger.AppLogger(args.quiet, args.verbose, None)

FEATURES = {}
FEATURES['notify'] = True
FEATURES['interface'] = None
FEATURES['tray'] = None

if args.interface == "gtk":
	try:
		from gi.repository import GObject
		# import gobject

		# pygtk require for local file resources (images)
		#import pygtk
		#pyGtk.require('2.0')
		from gi.repository import Gtk
		from gi.repository import Gdk
		from gi.repository import GdkPixbuf
		#import gtk
		FEATURES['tray'] = "gtk"
		FEATURES['interface'] = "gtk"

	except:
		logger.warn( "Could not load GTK. Trying fallback...")
		FEATURES['interface'] = False
		FEATURES['tray'] = False
else:
	logger.info( "Interface is text...")
	FEATURES['interface'] = False
	FEATURES['tray'] = False

logger.debug("Using interface:"+FEATURES['interface'])

if FEATURES['interface'] == "gtk":
	class AppNotifier:
		logger = None
		
		notifications = {}

		def __init__(self, logger):
			self.logger = logger

			if not Notify.init('Inactcli'):
				self.logger.error( "error initializing Notify.")
				exit_gracefully()
			self.logger.debug( "Nofity init.")

		def showMessage(self,filterName, message):
			try:
				pathDir = absolutePath()
				notification = Notify.Notification.new(
					"Inactcli",
					message, absolutePath+"/"+ICONS['active']['filename'])

					# Ubuntu needed this?
					#"notification-message-email")
				notification.set_urgency(Notify.Urgency.NORMAL)
				
				# Ubuntu needed this ? 
				#notification.set_hint_string("x-canonical-append","")
				#notification.attach_to_widget(self)
				if not notification.show():
					self.logger.warn( "Unable to show notification")
			except:
				self.logger.error("AppNotifier: Error:"+str(sys.exc_info()[0]))
				traceback.print_exc()
				
else:
	class AppNotifier:
		logger = None

		def __init__(self, logger):
			self.logger = logger
			self.logger.info( "notifier init: no interface. Falling back to terminal.")

		def showMessage(self, filterName, message):
			# TODO use logger?
			print (message)

if FEATURES['interface'] == "gtk":
	# FIXME this is not a class?
	class AboutDialog:
		def __init__(self, widget, event, logger):
#			self.logger = logger.newLogger('aboutDialog-gtk')
			
#			self.logger.debug('init')
			aboutdialog = Gtk.AboutDialog()
			
			aboutdialog.set_name("Inactmon-cli")
			aboutdialog.set_version("1.0")
			aboutdialog.set_copyright("Don't redistribute! ;)")
			aboutdialog.set_comments("Shows notifications about incomming activity based on pcap rules.")
			aboutdialog.set_authors(["Oliver Kuster"])

			absPath = absolutePath()

			# FIXME externalize
			logoPath = absPath+"/"+"../images/eye-version3-active.svg"
			logoImg = GdkPixbuf.Pixbuf.new_from_file_at_size(logoPath,100,100)
			aboutdialog.set_logo(logoImg)
#			self.logger.debug('done setting values, running')
			
		
			aboutdialog.run()
#			self.logger.debug('done running, destroying')
			
			aboutdialog.destroy()
#			self.logger.debug('done')
else:
	class AboutDialog:
		def __init__(self, widget, event, logger):
			self.logger = logger.newLogger('aboutDialog-none')
			self.logger.debug('init')
			self.logger.warn( "interface not specified...")
			self.logger.debug('done')

if FEATURES['tray'] == "gtk":
	class trayIcon(Gtk.StatusIcon):
		logger = None

		def __init__(self, statusMan, logger):
			self.logger = logger.newLogger('trayIcon-gtk')
			
			self.statusMan = statusMan
			Gtk.StatusIcon.__init__(self)
			
			pathDir = absolutePath()
			self.set_from_file(pathDir+"/"+ICONS['active']['filename'])
			#self.set_tooltip('Inactcli')
			self.set_visible(True)

			self.menu = menu = Gtk.Menu()

			self.status_item = status_item = Gtk.MenuItem("Disable")
			status_item.connect("activate", self.status_button, "status clicked")
			menu.append(status_item)

			about_item = Gtk.MenuItem("About")
			about_item.connect("activate", self.aboutdialog,"about")
			menu.append(about_item)

			quit_item = Gtk.MenuItem("Quit")
			quit_item.connect("activate", self.destroy_button, "file.quit")
			menu.append(quit_item)
			menu.show_all()

			self.connect('popup-menu', self.icon_clicked)

		def icon_clicked(self, status, button, time):
			self.menu.popup(None, None, None, None, button, time)

		def aboutdialog(self, widget, event=None):
			AboutDialog(widget, event, self.logger)

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
		logger = None

		def __init__(self,statusMan, logger):
			self.logger = logger.newLogger('trayIcon-none')
			
			self.statusMan = statusMan
			self.logger.debug( "class trayIcon for no interface loaded...")
		def setIcon(self, status, icon):
			#TODO:implement
			pass
		def setActionLabel(self,label):
			#TODO:implement
			self.logger.debug( "New label:"+label)



#FIXME:Fruit salad..
statusMan = appStatus()

trayLogger = logger.newLogger('trayIcon')
tray = trayIcon(statusMan, trayLogger)
statusMan.setTray(tray)

if FEATURES['interface'] == "gtk":
	Gdk.threads_init() # this makes gtk to allow threads =/

logger.info("Threading notificationManager")

notifierLogger = logger.newLogger('AppNotifier')
notifier = AppNotifier(notifierLogger)

notManLogger = logger.newLogger('notMan')
notMan = notificationManager( args.socketFile, statusMan, notManLogger, notifier)
notMan.setDaemon(True)
notMan.start()

try:
	if FEATURES['interface'] == "gtk":
		import signal
		signal.signal(signal.SIGINT, signal.SIG_DFL)
		Gtk.main()
	else:
		#just sleep?
		while(True):
			time.sleep(50)
			#print "."
except:
	logger.error( "main:Terminated! Error:"+str(sys.exc_info()[0]))
	#exit_gracefully()
