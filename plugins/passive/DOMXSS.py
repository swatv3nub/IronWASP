#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr
import re

#Inherit from the base PassivePlugin class
class DOMXSS(PassivePlugin):

	#From http://code.google.com/p/domxsswiki/wiki/FindingDOMXSS by Mario Heiderich
	sources = re.compile('/(location\s*[\[.])|([.\[]\s*["\']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)/')
	sinks = re.compile('/((src|href|data|location|code|value|action)\s*["\'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["\'\]]*\s*\()/')
	
	#Override the GetInstance method of the base class to return a new instance with details
	def GetInstance(self):
		p = DOMXSS()
		p.Name = "DOMXSSChecker"
		p.Version = "0.4"
		p.Description = "Passive plugin that checks the JavaScript in HTTP Response for DOM XSS Sources and Sinks."
		#When should this plugin be called. Possible values - BeforeInterception, AfterInterception, Both, Offline. Offline is the default value, it is also the recommended value if you are not going to perform any changes in the Request/Response
		#p.CallingState = PluginCallingState.BeforeInterception
		#On what should this plugin run. Possible values - Request, Response, Both
		p.WorksOn = PluginWorksOn.Response
		return p
	
	#Override the Check method of the base class with custom functionlity
	def Check(self, Sess, Results, ReportAll):	
		if(Sess.Request == None):
			return
		if(Sess.Response == None):
			return
		
		source_matches = []
		sink_matches = []
		
		JS = ""
		
		if(Sess.Response.IsHtml):
			scripts = Sess.Response.Html.GetJavaScript()
			scripts_js= []
			for script in scripts:
				scripts_js.append(script)
			JS = "\r\n".join(scripts_js)
		elif (Sess.Response.IsJavaScript):
			JS = Sess.Response.BodyString
		
		if JS == "":
			return
		
		for source_match in self.sources.findall(JS):
			for match in source_match:
				if(len(match) > 0):
					source_matches.append(match)
		for sink_match in self.sinks.findall(JS):
			for match in sink_match:
				if(len(match) > 0):
					sink_matches.append(match)
		
		source_matches = list(set(source_matches))
		sink_matches = list(set(sink_matches))
		
		if((len(source_matches) == 0) and (len(sink_matches) == 0)):
			return
		
		Signature = '{0}|{1}|{2}|{3}'.format(Sess.Request.UrlPath, Sess.Request.Method, ":".join(source_matches), ":".join(sink_matches))
		if ReportAll or self.IsSignatureUnique(Sess.Request.BaseUrl, FindingType.TestLead, Signature):
			Title = ""
			Summary = ""			
			if((len(source_matches) > 0) and (len(sink_matches) > 0)):
				Title = "DOM XSS Sources and Sinks found"
				Summary = "DOM XSS Sources and Sinks were found in the Body of the Response. Analyze the Response for presence of DOM XSS"
			elif(len(source_matches) > 0):
				Title = "DOM XSS Sources found"
				Summary = "DOM XSS Sources were found in the Body of the Response. Analyze the Response for presence of DOM XSS"
			elif(len(sink_matches) > 0):
				Title = "DOM XSS Sinks found"
				Summary = "DOM XSS Sinks were found in the Body of the Response. Analyze the Response for presence of DOM XSS"
			
			if(len(source_matches) > 0):
				trace_title = "<i<br>><i<h>>Sources:<i</hh>><i<br>>"
				source_trace = []
				for m in source_matches:
					source_trace.append("	{0}<i<br>>".format(m))
				Summary = "{0}{1}{2}".format(Summary, trace_title, "".join(source_trace))
			if(len(sink_matches) > 0):
				trace_title = "<i<br>><i<h>>Sinks:<i</hh>><i<br>>"
				sink_trace = []
				for m in sink_matches:
					sink_trace.append("	{0}<i<br>>".format(m))
				Summary = "{0}{1}{2}".format(Summary, trace_title, "".join(sink_trace))
			
			PR = Finding(Sess.Request.BaseUrl)
			PR.Title = Title
			PR.Summary = Summary
			PR.Triggers.Add("", "", Sess.Request, "\r\n".join(source_matches) + "\r\n" + "\r\n".join(sink_matches), "{0} DOM XSS Sources and {1} DOM XSS Sinks were found in the JavaScript contained in this response body".format(len(source_matches), len(sink_matches)), Sess.Response)
			PR.Type = FindingType.TestLead;
			PR.Signature = Signature
			Results.Add(PR)
			
p = DOMXSS()
PassivePlugin.Add(p.GetInstance())
