#!/usr/bin/python
"""
Author: Evan Poncelet 
Date:5/28/14
File: anchor.py
Purpose: This module contains definitions used by an anchor to send 802.11 frame digests to the MongoDB server 
"""

#Database communications
import pymongo  

#Time Stamping 
import ntplib  
from time import ctime

#Packet Sniffing
from scapy.all import *
from threading import Thread

#Editing config files and setting up monitor interface
from subprocess import Popen,PIPE
import re
import string

#Getting command line wireless interface argument or terminate on error
import sys


#@@@@@@@Global Definitions Identifying This Particular Anchor@@@@@@@@@@@@
ANCHOR_ID = "0" # Global value, must be unique for each anchor, identifying this hardware device.    
ANCHOR_XY = (0,0) # Global value, must be uneque for each anchor, identifies the relative geographic x and y position in meters on a floor map at which this anchor is located 



'''
Purpose: This method sets up an ntpClient connection to an ntp server 
Preconditions: A geographically close ntp server address is the ntpServer argument, 
Postconditions: A response from the requested ntpserver is issued confirming its ip address
#notes: For greater accuracy in 10's of ~usec, use PPS from gps module(s) on a raspberry pi in kernel mode and use it as an NTP server. 
#       Only the antenna needs a clear view of a part of the sky for  PPS to work. 
'''

def ntpClientInit(ntpServer):
    ntpClient = ntplib.NTPClient()
    try:
    	response = ntpClient.request(ntpServer)
    	print "Client Initialized"
        return ntpClient
    except Exception as (errno, strerror):
                        print "NTP error({0}): {1}".format(errno, strerror)
                        print "Could not connect to NTP Server"
			exit(2)
                        return None


'''
Purpose: This method makes a request of the current time from the ntpClient
Preconditions: The ntpClientInit method has been called exactly once to initialize the ntpClient interface which is the argument, and the ntpServer responded to the init request
Postconditions: The number of seconds since the epoch date of Jan 1, 1900 is returned  
'''
def ntpTime(ntpClient, ntpServer):
  
    try:
        response = ntpClient.request(ntpServer)
        return response.tx_time
    except Exception, errno:
        		print "Could not get time from NTP Server" 
                        print "NTP error({0})".format(errno) 
        		return None


'''
Purpose: This method connects a client app to a MongoDB server instance and returns the connection
Preconditions: A Mongod process is running on a server with the ip of the serverIP argument  and 
               the port in the port argument listening.   
Postconditions: the connection to the server is returned and the status of the connection is ouput
                to the console
'''
def connectToServer(serverIP, port):
        serverID = "mongodb://" + serverIP + ":" + port 
	try:
		conn = pymongo.MongoClient(serverID)
        	print "MongoDB server connection success"
	except pymongo.errors.ConnectionFailure, e:
		print "Could not connect to MongoDB server: %s" % e
		exit(2)
	return conn

'''
Purpose: show all of the databases in the mongoDB server 
Preconditions: the conn argument contains a valid connection to a MongoDB server
Postconditions: each of the MongoDB databases in the connected server are printed
'''

def showDBs(conn):
	for i in conn.database_names():
           print i

'''
purpose: locate and return the first substring in searchSpace to match the regular expression, regEx. Also, return true or
         false if an exact match is found for matchTarget or not
'''
def regExHelper(regEx, searchSpace, matchTarget):
	helperRegex = re.compile(regEx)
        matchFound = None
        match = "No Match Located"
        if('\n' in searchSpace):
        	searchSpace = searchSpace.split('\n')
		for line in searchSpace:
			matchFound = None
			matchFound = helperRegex.search(line)
			if not matchFound is None:
				if(matchFound.group(0) == matchTarget):
					return (matchFound.group(0), True)
				else:
					match = matchFound.group(0)
		return (match, False)
	else:
		matchFound = helperRegex.search(searchSpace)
		if not matchFound is None:
			if(matchFound.group(0) == matchTarget):
				return (matchFound.group(0), True)
			else:
				return (matchFound.group(0), False)

'''
purpose: make a linux command and return whatever text is sent to standard out as a result of that command for later parsing
'''
def callAndResult(command):
	result = ""
	process = Popen(command, stdout=PIPE, shell = True)
	process.wait()
	callResult = process.communicate()[0]
	if (callResult is not None):
		result = callResult
        return result

'''
purpose: check to see if the desired wlan is available and output a message confirming or denying that the wlan is available 
'''
def checkWlan(wlan):
	wlanCheck = wlan
        print "Checking if " + wlan + " is up and functioning..." 
	calltoLinux = string.replace("ifconfig " + wlanCheck + " up", "\n", "") #First bring up the interface just in case it is down
        callAndResult(calltoLinux)
        calltoLinux = string.replace("ifconfig", "\n", "") 
        callResult = callAndResult(calltoLinux)
        checkAnswer = regExHelper(wlanCheck, callResult, wlanCheck)
	if((checkAnswer is not None) and (checkAnswer[1])):
	     print "interface:" + wlan + " is up and functioning."
             return True
        else:
             print "interface:" + wlan + " is not found, reinsert USB adapter."
	     exit(2)
	

'''
Purpose: Start a monitor interface on the wlan interface for promiscuous mode and edit the scapy configuration file to 
         use the monitor interface for packet sniffing
Preconditions: The scapy configuration file exists with default configurations and the wlan interface is up
Postconditions: The scapy configuration file has it's interface changed to the monitor interface and the monitor interface
                name is returned so that it can be closed when the program exits
TODO: this is where the channel should be set as well once hardware is available with that ability 
'''
def setMonitor(wlan):
        if( checkWlan(wlan) ):
		callToLinux = string.replace("airmon-ng start " + wlan, "\n", "")
                possibleMonitors = callAndResult(callToLinux)
		mon = regExHelper("mon\d", possibleMonitors, "")
		if(mon[0] is not None):
			mon = mon[0]
                        scapy.config.conf.iface = mon
                        print "The monitor interface to be used is: " + mon
                        return mon
        else:
        	print "The monitor could not be set because the WLan interface was not found."
                exit(2)

'''
Purpose: Remove the monitor interface being used by the application
Preconditions: The monitor interface of the mon argument has been set only once previously using setMonitor on the wlan interface
PostConditions: The monitor interface is removed and is no longer seen in the interface configuration
'''
def removeMonitor(mon):
	callToLinux = string.replace("airmon-ng stop " + mon, "\n", "")
        print "removing monitor interface: " + mon
        callAndResult(callToLinux)
        print mon + " is removed."




'''
Purpose: packet handler for Probe request frames from clients puts timestamp, MAC address, SSID of interest, and RSSI in database
Notes: since the callback function for scapy packet filtering must be single argument, a Pythonic parent function is used to bind additional arguments
'''
def packetHandler(ntpClient, ntpServer, collection):
	def packetParser(pkt):
		if pkt.haslayer(Dot11):
			if(pkt.type, pkt.subtype) == (0,4):
				timeStamp = ntpTime(ntpClient,ntpServer) #don't include packets without a timestamp in the database, they don't match search queries and are thustly useless
				if(timeStamp is not None):
					print "Station MAC: {} has RSSI: {} and time stamp: {} seen from Anchor: {} at x: {} and y: {}".format(pkt.addr2, -(255-ord(pkt.notdecoded[-4:-3])),ctime(timeStamp), ANCHOR_ID, ANCHOR_XY[0], ANCHOR_XY[1])
                                        post = {"AnchorID": ANCHOR_ID,
						"AnchorX" : ANCHOR_XY[0],
						"ANCHORY" : ANCHOR_XY[1],
						"Station_MAC":pkt.addr2,
						"RSSI": -(255-ord(pkt.notdecoded[-4:-3])),
						"TimeStamp": timeStamp }
					postID = collection.insert(post)
                                        print postID
					
        return packetParser
	

'''
purpose: thread for sniffer method since it is blocking and it needs to be stopped upon SIGINT 
         while allowing the monitor interface to be shut off before program exit
preconditions: takes monitor interface, the ntp client returned from the clientInit method, the ntp server address, the connection to the database, and the database name  
'''
class SnifferThread(Thread):
	def __init__ (self, monitor, ntpClient, ntpServer, collection):
		Thread.__init__(self)
		self.monitor = monitor
                self.ntpClient = ntpClient
		self.ntpServer = ntpServer
                self.collection = collection
        
        def run(self):
		try: 
			sniff(iface=self.monitor, prn=packetHandler(self.ntpClient, self.ntpServer, self.collection))
		except IOError as (errno, strerror):
			print "I/O error({0}): {1}".format(errno, strerror) 


'''
purpose: this method implements the application logic 
'''
def main():
          
        #initialization of ntp and database
        ntpServer = "bigben.cac.Washington.edu"
        ntpClient = ntpClientInit(ntpServer)
        dataBaseID = "packetDigests"
        collectionID = "timedFrames"
	conn = connectToServer("192.168.2.29","27017")
        monitor = setMonitor(sys.argv[1])
        database = conn[dataBaseID]
        collection = database[collectionID]   
        

        sniffer = SnifferThread(monitor, ntpClient, ntpServer, collection)
        sniffer.start()

        #Start putting packets in the database
        try:
               while(1):
			pass

        except KeyboardInterrupt:
		#unfortunately, joining the snifferThread is not possible because it does not terminate unless sent SIGINT  and joining here only blocks
                #until it does...which is never. 
        	removeMonitor(monitor) #pull the network out to generate IO exception and kill the sniffer. May cause memory leak, but workaround is reboot after fail
     


if __name__=="__main__":
	main() 	

