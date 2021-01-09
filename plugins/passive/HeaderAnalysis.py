#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr

#Inherit from the base PassivePlugin class
class HeaderAnalysis(PassivePlugin):

	#Override the GetInstance method of the base class to return a new instance with details
	def GetInstance(self):
		p = HeaderAnalysis()
		p.Name = "Header Analysis"
		p.Version = "0.4"
		p.Description = "Analyzes the HTTP Request and Response Headers for potential security issues"
		#When should this plugin be called. Possible values - BeforeInterception, AfterInterception, Both, Offline. Offline is the default value, it is also the recommended value if you are not going to perform any changes in the Request/Response
		#p.CallingState = PluginCallingState.BeforeInterception
		#On what should this plugin run. Possible values - Request, Response, Both
		p.WorksOn = PluginWorksOn.Response
		return p
	
	#Override the Check method of the base class with custom functionlity
	def Check(self, Sess, Results, ReportAll):
		
		self.ReportAll = ReportAll
		
		if Sess.Response.Headers.Has("Location") and Sess.Response.Code != 200:
			actual_redirect_location = Sess.Response.Headers.Get("Location")
			redirect_location = actual_redirect_location.lower()
			for part in Sess.Request.UrlPathParts:
				if part.lower() == redirect_location:
					self.ReportRedirect(actual_redirect_location, part, "url", Sess, Results)
					return
			for name in Sess.Request.Query.GetNames():
				for val in Sess.Request.Query.GetAll(name):
					if val.lower() == redirect_location:
						self.ReportRedirect(actual_redirect_location, val, "query:(0)".format(name), Sess, Results)
						return
			for name in Sess.Request.Body.GetNames():
				for val in Sess.Request.Body.GetAll(name):
					if val.lower() == redirect_location:
						self.ReportRedirect(actual_redirect_location, val, "body:{0}".format(name), Sess, Results)
						return
			if Sess.Request.Headers.Has("Referer"):
				if Sess.Request.Headers.Get("Referer").lower() == redirect_location:
					self.ReportRedirect(actual_redirect_location, Sess.Request.Headers.Get("Referer"), "referrer", Sess, Results)
					return

	def ReportRedirect(self, redirect_location, val, section, Sess, Results):
		Signature = '{0}|{1}'.format(Sess.Request.SSL.ToString(), section)
		if self.ReportAll or self.IsSignatureUnique(Sess.Request.BaseUrl, FindingType.TestLead, Signature):
			PR = Finding(Sess.Request.BaseUrl)
			PR.Title = "Possible Open Redirect"
			PR.Summary = "The Location Header of the Response contains the value present in the Request. This could potentially be an Open Redirect. Manual investigation required."
			
			if section == "url":
				PR.Triggers.Add(redirect_location, "The response is redirecting to {0}, this value is found in the url path section of this request".format(redirect_location), Sess.Request, redirect_location, "This response is a redirect to the location {0}".format(redirect_location), Sess.Response)
			elif section.startswith("query:"):
				PR.Triggers.Add(redirect_location, "The response is redirecting to {0}, this value is found in the {1} parameter of query section of this request".format(redirect_location, section[6:]), Sess.Request, redirect_location, "This response is a redirect to the location {0}".format(redirect_location), Sess.Response)
			elif section.startswith("body:"):
				PR.Triggers.Add(redirect_location, "The response is redirecting to {0}, this value is found in the {1} parameter of body section of this request".format(redirect_location, section[5:]), Sess.Request, redirect_location, "This response is a redirect to the location {0}".format(redirect_location), Sess.Response)
			elif section == "referrer":
				PR.Triggers.Add(redirect_location, "The response is redirecting to {0}, this value is found in the referrer header of this request".format(redirect_location), Sess.Request, redirect_location, "This response is a redirect to the location {0}".format(redirect_location), Sess.Response)
			
			PR.Signature = Signature
			PR.Type = FindingType.TestLead
			Results.Add(PR)
		
	
p = HeaderAnalysis()
PassivePlugin.Add(p.GetInstance())
