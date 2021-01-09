#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *

class HTMLAnalysis(PassivePlugin):
    
	#Override the GetInstance method of the base class to return a new instance with details
	def GetInstance(self):
		p = HTMLAnalysis()
		p.Name = "HTML Analysis"
		p.Version = "0.4"
		p.Description = "Passive plugin to analyze the Response HTML for potential vulnerabilities"
		p.FileName = "HTMLAnalysis.py"
		p.WorksOn = PluginWorksOn.Response
		return p
	
	def Check(self, Sess, Results, ReportAll):
		
		if(Sess.Response.IsBinary):
			return
		
		if(not Sess.Response.IsHtml):
			return
	
		self.Sess = Sess
		self.Results = Results
		self.ReportAll = ReportAll
		
		Req = Sess.Request
		Res = Sess.Response
		
		script_srcs = Sess.Response.Html.GetValues("script","src")
		for src in script_srcs:
			try:
				src_req = Request(src)
				if(self.IsForiegnDomain(Req, src_req)):
					self.ReportScriptFromExternalDomain()
					Title = "Scripts loaded from External Domains"
					Summary = "Script has been loaded in the page from {0} which is an external domain that might not be trustworthy".format(src_req.Host)
					Signature = self.MakeSignature(Title, src_req.Host)
					self.ReportTestLead(Title, Summary, Req.BaseUrl,"This request is made to the domain - {0}".format(Req.Host),src_req.FullUrl,"This response loads a JavaScript document from the domain - {0}".format(src_req.Host), Signature)
				if(Req.SSL and not src_req.SSL):
					Title = "Insecure Scripts loaded inside Secure Page"
					Summary = "Page loaded over SSL includes script that is loaded over HTTP, this compromises the integrity of the SSL layer"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportVulnerability(Title, Summary, "https://","This Request was made over HTTPS",src_req.FullUrl,"This response loads a JavaScript document from the HTTP url {0}".format(src_req.BaseUrl), FindingConfidence.High, FindingSeverity.Medium, Signature)
				elif(src_req.SSL and not Req.SSL):
					Title = "Secure Script loaded inside Insecure Page"
					Summary = "Page loaded over HTTP includes script that is loaded over SSL, this compromises the integrity of the script"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportTestLead(Title, Summary, "http://","This Request was made over HTTP",src_req.FullUrl,"This response loads a JavaScript document from the SSL url {0}".format(src_req.BaseUrl), Signature)
			except:
				pass
			
		css_srcs = Sess.Response.Html.GetValues("style","src")
		for src in css_srcs:
			try:
				src_req = Request(src)
				if(self.IsForiegnDomain(Req, src_req)):
					Title = "CSS loaded from External Domains"
					Summary = "CSS document has been loaded in the page from {0} which is an external domain that might not be trustworthy".format(src_req.Host)
					Signature = self.MakeSignature(Title, src_req.Host)
					self.ReportTestLead(Title, Summary, Req.BaseUrl,"This request is made to the domain - {0}".format(Req.Host),src_req.FullUrl,"This response loads a CSS document from the domain - {0}".format(src_req.Host), Signature)
				if(Req.SSL and not src_req.SSL):
					Title = "Insecure CSS loaded inside Secure Page"
					Summary = "Page loaded over SSL includes CSS that is loaded over HTTP, this compromises the integrity of the SSL layer"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportVulnerability(Title, Summary, "https://","This Request was made over HTTPS",src_req.FullUrl,"This response loads a CSS document from the HTTP url {0}".format(src_req.BaseUrl), FindingConfidence.High, FindingSeverity.Medium, Signature)
			except:
				pass
		
		iframe_srcs = Sess.Response.Html.GetValues("iframe","src")
		for src in iframe_srcs:
			try:
				src_req = Request(src)
				if(self.IsForiegnDomain(Req, src_req)):
					Title = "IFRAME loaded from External Domains"
					Summary = "IFRAME has been loaded in the page from {0} which is an external domain that might not be trustworthy".format(src_req.Host)
					Signature = self.MakeSignature(Title, src_req.Host)
					self.ReportTestLead(Title, Summary, Req.BaseUrl,"This request is made to the domain - {0}".format(Req.Host),src_req.FullUrl,"This response contains an IFRAME from the domain - {0}".format(src_req.Host), Signature)
				if(Req.SSL and not src_req.SSL):
					Title = "Insecure IFRAMEs loaded inside Secure Page"
					Summary = "Page loaded over SSL includes IFRAME that is loaded over HTTP, this compromises the integrity of the SSL layer"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportVulnerability(Title, Summary, "https://","This Request was made over HTTPS",src_req.FullUrl,"This response contains an IFRAME from the HTTP url {0}".format(src_req.BaseUrl), FindingConfidence.High, FindingSeverity.Medium, Signature)
				elif(src_req.SSL and not Req.SSL):
					Title = "Secure IFRAME loaded inside Insecure Page"
					Summary = "Page loaded over HTTP includes IFRAME that is loaded over SSL, this compromises the integrity of the IFRAME"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportTestLead(Title, Summary, "http://","This Request was made over HTTP",src_req.FullUrl,"This response contains an IFRAME from the SSL url {0}".format(src_req.BaseUrl), Signature)
			except:
				pass
		
		forms = Sess.Response.Html.GetForms()
		#form_actions = Sess.Response.Html.GetValues("form","src")
		for form in forms:
			src = self.GetFormAction(form)
			form_signature = self.GetFormSignature(form)
			try:
				src_req = Request(src)
				if(self.IsForiegnDomain(Req, src_req)):
					Title = "Form contents submitted to External Domains"
					Summary = "Form contents in the page are submitted to {0} which is an external domain that might not be trustworthy".format(src_req.Host)
					Signature = self.MakeSignature(Title, "{0}{1}".format(src_req.Host, form_signature))
					self.ReportTestLead(Title, Summary, Req.BaseUrl,"This request is made to the domain - {0}".format(Req.Host),src_req.FullUrl,"An HTML form loaded from {0} is submitted to {1}".format(Req.Host, src_req.Host), Signature)
				if(Req.SSL and not src_req.SSL):
					if(self.IsSensitiveForm(form, form_signature)):
						Title = "Secure Page submits Sensitive Form contents to InSecure Page"
						Summary = "Form contained inside page loaded over SSL submits its contents, which includes password fields, to another page over HTTP"
						Signature = self.MakeSignature(Title, form_signature)
						self.ReportVulnerability(Title, Summary, "https://","This Request was made over HTTPS",src_req.FullUrl,"An HTML form in this response which contains password fields, submits its contents to the HTTP url - {0}".format(src_req.FullUrl) ,FindingConfidence.High, FindingSeverity.Medium, Signature)
					else:
						Title = "Secure Page submits Form contents to InSecure Page"
						Summary = "Form contained inside page loaded over SSL submits its contents to another page over HTTP"
						Signature = self.MakeSignature(Title, form_signature)
						self.ReportVulnerability(Title, Summary, "https://","This Request was made over HTTPS",src_req.FullUrl,"An HTML form in this response submits its contents to the HTTP url - {0}".format(src_req.FullUrl), FindingConfidence.High, FindingSeverity.Low, Signature)
				elif(src_req.SSL and not Req.SSL):
					if(self.IsSensitiveForm(form, form_signature)):
						Title = "Secure Form with Sensitive contents loaded over InSecure Page"
						Summary = "Form contained inside page loaded over HTTP submits its contents, which includes password fields, to another page over HTTPS. Loading the form over HTTP compromises the SSL security required for this form submission."
						Signature = self.MakeSignature(Title, form_signature)
						self.ReportVulnerability(Title, Summary, "http://","This Request was made over HTTP",src_req.FullUrl,"An HTML form in this response which contains password fields, submits its contents to the HTTPS url - {0}".format(src_req.FullUrl), FindingConfidence.High, FindingSeverity.Medium, Signature)
					else:
						Title = "Secure Form loaded over InSecure Page"
						Summary = "Form contained inside page loaded over HTTP but submits its contents to another page over HTTPS. Loading the form over HTTP compromises the SSL security required for this form submission."
						Signature = self.MakeSignature(Title, form_signature)
						self.ReportVulnerability(Title, Summary, "http://","This Request was made over HTTP",src_req.FullUrl,"An HTML form in this response submits its contents to the HTTPS url - {0}".format(src_req.FullUrl), FindingConfidence.High, FindingSeverity.Low, Signature)
			except:
				if(self.IsSensitiveForm(form, form_signature) and not Req.SSL):
					Title = "Sensitive Form loaded and submitted Insecurely"
					Summary = "Form with sensitive contents, which includes password fields, is loaded and submitted over HTTP"
					Signature = self.MakeSignature(Title, form_signature)
					self.ReportVulnerability(Title, Summary, "http://","This Request was made over HTTP",form.OuterHtml,"The HTML form containing password fields is displayed below. The unnecessary elements from this form have been stripped away for clarity.", FindingConfidence.High, FindingSeverity.Medium, Signature)
		
	def IsSensitiveForm(self, form, form_signature):
		AutoComplete = True
		Sensitive = False
		for attr in form.Attributes:
			if(attr.Name.lower() == "autocomplete"):
				if(attr.Value.lower() == "off"):
					AutoComplete = False
		
		for child_node in form.ChildNodes:
			if(child_node.Name.lower() == "input"):
				Sensitive = False
				pwd_field = False
				field_autocomplete = AutoComplete
				
				for attr in child_node.Attributes:
					attr_name = attr.Name.lower()
					if(attr_name == "type" and attr.Value.lower() == "password"):
						Sensitive = True
						pwd_field = True
					if attr_name == "autocomplete" and attr.Value.lower() == "off" :
						field_autocomplete = False
				if (Sensitive and AutoComplete) or (pwd_field and field_autocomplete):
					Title = "AutoComplete Enabled on Password Fields"
					Summary = "AutoComplete feature has not been disabled on the form/fields that accept Passwords from users"
					Signature = self.MakeSignature(Title, form_signature)
					self.ReportVulnerability(Title, Summary,"","","","This response contains INPUT elements whose type attribute is password but their autocomplete attribute is not set to 'off'",FindingConfidence.High, FindingSeverity.Low, Signature)
					return True
		return False
	
	def GetFormAction(self, form):
		for attr in form.Attributes:
			if(attr.Name.lower() == "action"):
				return attr.Value 
		return ""
	
	def GetFormSignature(self, form):
		form_signature = []
		for attr in form.Attributes:
			attr_name = attr.Name.lower()
			form_signature.append(attr_name)
			if attr_name == "id" or attr_name == "class" or attr_name == "method":
				form_signature.append(attr.Value)
		
		for child_node in form.ChildNodes:
			if(child_node.Name.lower() == "input"):
				for attr in child_node.Attributes:
					attr_name = attr.Name.lower()
					if attr_name == "name":
						form_signature.append(attr_name)
						form_signature.append(attr.Value)
		return "|".join(form_signature)
	
	def IsForiegnDomain(self, ReqOne, ReqTwo):
		reqone_host_parts = ReqOne.Host.Split(".")
		reqtwo_host_parts = ReqTwo.Host.Split(".")
		
		if((self.IsIP(ReqOne.Host) or self.IsIP(ReqTwo.Host)) or (len(reqone_host_parts) < 1 or len(reqtwo_host_parts) < 1)):
			if(ReqOne.Host == ReqTwo.Host):
				return False
			else:
				return True
		
		if((reqone_host_parts[0] == reqtwo_host_parts[0]) and (reqone_host_parts[1] == reqtwo_host_parts[1])):
			return False
		else:
			return True
	
	def IsIP(self, Input):
		vals = Input.split(".")
		if(len(vals) != 4):
			return False
		int_vals = []
		for val in vals:
			try:
				int_val = int(val)
				int_vals.append(int_val)
			except:
				return False
		if(int_vals[0] < 1 or int_vals[0] > 222):
			return False
		for i in range(1,4):
			if(int_vals[i] < 0 or int_vals[i] > 255):
				return False
		return True
		
		
	def ReportVulnerability(self, Title, Summary, RequestTrigger, RequestTriggerDesc, ResponseTrigger, ResponseTriggerDesc, Confidence, Severity, Signature):
		#Results = ThreadStore.Get("Results")
		#Sess = ThreadStore.Get("Session")
		if self.ReportAll or self.IsSignatureUnique(self.Sess.Request.BaseUrl, FindingType.Vulnerability, Signature):
			PR = Finding(self.Sess.Request.BaseUrl)
			PR.Title = Title
			PR.Summary = Summary
			PR.Triggers.Add(RequestTrigger, RequestTriggerDesc, self.Sess.Request, ResponseTrigger, ResponseTriggerDesc, self.Sess.Response)
			PR.Signature = Signature
			PR.Confidence = Confidence
			PR.Severity = Severity
			self.Results.Add(PR)
		
	def ReportTestLead(self, Title, Summary, RequestTrigger, RequestTriggerDesc, ResponseTrigger, ResponseTriggerDesc, Signature):
		#Results = ThreadStore.Get("Results")
		#Sess = ThreadStore.Get("Session")
		if self.ReportAll or self.IsSignatureUnique(self.Sess.Request.BaseUrl, FindingType.TestLead, Signature):
			PR = Finding(self.Sess.Request.BaseUrl)
			PR.Title = Title
			PR.Summary = Summary
			PR.Triggers.Add(RequestTrigger, RequestTriggerDesc, self.Sess.Request, ResponseTrigger, ResponseTriggerDesc, self.Sess.Response)
			PR.Signature = Signature
			PR.Type = FindingType.TestLead
			self.Results.Add(PR)

	def MakeSignature(self, Title, VulnSignature):
		#Sess =  ThreadStore.Get("Session")
		Signature = '{0}|{1}|{2}|{3}:'.format(self.Sess.Request.SSL.ToString(), self.Sess.Request.Method, Title, VulnSignature)
		return Signature


p = HTMLAnalysis()
PassivePlugin.Add(p.GetInstance())
