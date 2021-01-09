import clr
clr.AddReference("System")
clr.AddReference("System.Data")
clr.AddReference("System.Data.SQLite")

import System
from System.Data.SQLite import *
import fingerprint
#import httppages
from IronWASP import *
import webservices as ws

class dbwrite():
	
	def __init__(self, isap):
		self.isap = isap
		pass
	def pingwrite(self,values):
		pass
		#self.isap.print_out("Writing Ping values to DB\r\n", 0)
		#for x in values:
		#	print x
	def portscanwrite(self,values):
		#self.isap.print_out("Writing PortScan values to DB\r\n", 0)
		self.isap.print_out("\r\nPort Scan Result (arranged by the associated service) :\r\n", 1)
		port_count = 0
		for value in values.iterkeys():
			if value != "ip" and value != "actid":
				port_count = port_count + len(values[value])
				self.isap.print_out(value+": " + self.port_list_to_str(values[value]), 1)
		if port_count > 0:
			fp1 = fingerprint.fingerprint(values, self.isap)
			fp1.starts()
		else:
			self.isap.print_out("\r\nNo open ports found. Cannot proceed further.", 1)
			self.isap.stopper()
		
	def fingerprintwrite(self,response200,response404,response401,values):
		#print response200,response404,response401,values
		#print "Displaying HTML Analysis Results:"
		
		if self.isap.verbose:
			self.isap.print_out("Responses for Requests that returned a Response 200:" + str(response200) + "\r\n", 2)
			self.isap.print_out("\r\n", 2)
			self.isap.print_out("Information Gathered from Error Pages:" + str(response404) + "\r\n", 2)
			self.isap.print_out("\r\n", 2)
			self.isap.print_out("Result of Verb Tampering:" + str(response401) + "\r\n", 2)
		#ws = webservices.webservices(values)
		#ws.start()
		 
#		print "Detailed Page Analysis Results:","\n"
#		print pagechecker
		#hp = httppages.httppages()
		#hp.starts()
	
	def port_list_to_str(self, port_list):
		if len(port_list) == 0:
			return " -"
		else:
			res = ""
			for port in port_list:
				res = str(port) + ", "
			return res.strip().rstrip(",")
		
		
		
		

		

 	