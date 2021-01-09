#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System.Threading import Monitor
import re

class CheckReflection(PassivePlugin):
    
	#Override the GetInstance method of the base class to return a new instance with details
	def GetInstance(self):
		p = CheckReflection()
		p.Name = "Check Reflections"
		p.Version = "0.4"
		p.Description = "Passive plugin to identify stored reflections"
		#p.CallingState = PluginCallingState.BeforeInterception
		p.WorksOn = PluginWorksOn.Response
		return p
	
	def Check(self, Sess, Results, ReportAll):
	
		if(Sess.Request == None):
			return
		
		if(Sess.Response == None):
			return
		
		if not (Sess.Response.IsHtml or Sess.Response.IsXml or Sess.Response.IsJavaScript or Sess.Response.IsJson):
			return
		
		#Get the probe strings injected by the XSS Plugin during XSS Scans
		probe_strings = Analyzer.GetProbeStrings()
		if len(probe_strings) == 0:
			return
		
		ReqStr = Sess.Request.ToString()
		ResStr = Sess.Response.ToString()
		
		matching_probe_strings = []
		
		for ps in probe_strings:
			if(ReqStr.count(ps) == 0):
				if(ResStr.count(ps) > 0):
					matching_probe_strings.append(ps)
		
		if(len(matching_probe_strings) > 0):
			Signature = '{0}|{1}'.format(Sess.Request.UrlPath, "-".join(matching_probe_strings))
			if ReportAll or self.IsSignatureUnique(Sess.Request.BaseUrl, FindingType.TestLead, Signature):
				PR = Finding(Sess.Request.BaseUrl)
				PR.Title = "Stored Reflection Found on {0}".format(Sess.Request.URLPath)
				PR.Summary = "Probe Strings injected during XSS Scans were found to be reflected in this page. This indicates a Stored Reflection, test this for Stored XSS."
				PR.Triggers.Add("", "", Sess.Request, "\r\n".join(matching_probe_strings), "Probe Strings found in the response body", Sess.Response)
				for mps in matching_probe_strings:
					PR.Triggers.Add(mps, Analyzer.GetProbeStringRequest(mps))
				PR.Type = FindingType.TestLead
				PR.Signature = Signature
				Results.Add(PR)
        

p = CheckReflection()
PassivePlugin.Add(p.GetInstance())
