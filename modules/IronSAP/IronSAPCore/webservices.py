from IronWASP import *
import clr
clr.AddReference("System.Web.Services")
clr.AddReference("System.Xml")

from System.Web.Services.Description import (
    ServiceDescription, ServiceDescriptionImporter
)
from System.Web.Services.Protocols import SoapHttpClientProtocol
from System.IO import MemoryStream
from System.Net import WebClient

from System.CodeDom import (
    CodeCompileUnit, CodeNamespace
)
from System.CodeDom.Compiler import CodeDomProvider, CompilerParameters
from System.Xml.Serialization import CodeGenerationOptions

class webservices:
	
	
	def returnres(self,op):
		proto = "http://"
		#f = open("SAPstart.txt")
		ip = self.values["ip"]
		for x in self.ports:
			#print x
			try:
				Request("http://" + ip + ":" + str(x)).Send()
			except:
				try:
					Request("https://" + ip + ":" + str(x)).Send()
					proto = "https://"
				except:
					pass
			url = proto + ip + ":" + str(x) + "/SAPControl.cgi"
			strin = self.strings[op]
			req = Request("POST",url,strin)
			resp = req.Send()
			self.isap.print_out(resp,3)
			#f.write(resp)
		#f.close()
			
	
	
	def CreateWebServiceFromWsdl(self,wsdl):
		sd = ServiceDescription.Read(MemoryStream(wsdl))
		ptcount= sd.PortTypes.Count
		self.isap.print_out("Port Types:"+str(ptcount),3)
		for x in range(0,ptcount):
			self.isap.print_out(str(sd.PortTypes[x].Name),3)
			portoperations = sd.PortTypes[x].Operations
			portoperationscount = portoperations.Count
			self.isap.print_out("Operations"+str(portoperationscount),3)
			for j in range(0,portoperationscount):
				self.isap.print_out(str(portoperations[j].Name),3)
		self.returnres("GetProcessList")
			
	def GetWebservice(self,url):
		 data = self.GetBytes(url)
		 assembly = self.CreateWebServiceFromWsdl(data)
	def GetBytes(self,url):  
		return WebClient().DownloadData(url)
	
	def __init__(self,values,isap):
		self.isap=isap
		self.values = values
		self.ports =[]
		self.operations=[]
		self.strings={"ParameterValue":'<?xml version="1.0" encoding="UTF-8" ?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema"><SOAP-ENV:Header><sapsess:Session xmlns:sapsess="http://www.sap.com/webas/630/soap/features/session/"><enableSession>true</enableSession></sapsess:Session></SOAP-ENV:Header><SOAP-ENV:Body><ns1:ParameterValue xmlns:ns1="urn:SAPControl"><parameter></parameter></ns1:ParameterValue></SOAP-ENV:Body></SOAP-ENV:Envelope>',"GetProcessList":'<?xml version="1.0" encoding="UTF-8" ?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema"><SOAP-ENV:Header><sapsess:Session xmlns:sapsess="http://www.sap.com/webas/630/soap/features/session/"><enableSession>true</enableSession></sapsess:Session></SOAP-ENV:Header><SOAP-ENV:Body><ns1:GetProcessList xmlns:ns1="urn:SAPControl"></ns1:GetProcessList></SOAP-ENV:Body></SOAP-ENV:Envelope>'}
	
	def start(self):
		self.isap.print_out("Starting SAP START WebService Analysis"+"\n",0)
		startserviceports = []
		for port in self.values["Start Service"]:
			startserviceports.append(port)
			self.ports.append(port)
		#self.isap.print_out(len(startserviceports),0)
		if len(startserviceports) > 0:
		 self.analysis(startserviceports)
		else:
			self.isap.print_out("NO SAP START ports were found ",3)
			self.isap.stopper()

		
	def analysis(self,ports):
		ip = self.values["ip"]
		for port in ports:
			self.isap.print_out("Port Type/Operations for For for Port"+str(port)+"\n")
			proto = "http://"
			try:
				Request("http://" + str(ip) + ":" + str(port)).Send()
			except:
				try:
					Request("https://" + str(ip) + ":" + str(port)).Send()
					proto = "https://"
				except:
					pass
				
			url = proto + str(ip) + ":" + str(port) + "/?wsdl"
			req = Request(url)
			resp = req.Send()
			if resp.Code==200:
				pr = PluginResult(req.Host)
				pr.Title = "SAP Start Service (MMC) was found"
				pr.Summary = "SAP Start service could be used to retrive a lot of business critical data from the SAP system"
				pr.Plugin = " "
				pr.Triggers.Add("",req,"",resp)
				g = PluginResultSeverity.High
				h = PluginResultConfidence.High
				pr.Severity = g
				pr.Confidence =h
				pr.Report()
			self.GetWebservice(url)
#			req = Request(url)
#			req.Headers.Set("User-Agent","Mozilla/5.0 (Windows NT 5.1; rv:14.0) Gecko/20100101 Firefox/14.0.1")
#			resp = req.Send()
#			if resp.Code==200:
#				print resp