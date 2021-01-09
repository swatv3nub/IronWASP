#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
import re

class SessionAnalysis(PassivePlugin):
    
  #Override the GetInstance method of the base class to return a new instance with details
  def GetInstance(self):
    p = SessionAnalysis()
    p.Name = "Session Analysis"
    p.Description = "Passive plugin to analyze the Session for potential vulnerabilities"
    p.Version = "0.5"
    p.FileName = "SessionAnalysis.py"
    p.WorksOn = PluginWorksOn.Response
    return p
  
  def Check(self, Sess, Results, ReportAll):

    self.Sess = Sess
    self.Results = Results
    self.ReportAll = ReportAll
    #ThreadStore.Put("Session", Sess)
    #ThreadStore.Put("Results", Results)
    
    #Check if this is a response for authentication
    if self.IsLoginRequest(Sess.Request):
      if Sess.Response.SetCookies.Count == 0 and Sess.Request.Cookie.Count > 0:
        Summary = "The application does not set a new Session ID in the cookie after what appears to be an authentication attempt by the user. If this was a successful login and the Session IDs are stored in cookies then this application is affected by Session Fixation vulnerability."
        self.ReportSessionFixation(Summary, "", "", "", "", FindingConfidence.Low, FindingSeverity.Medium)
      elif Sess.Response.SetCookies.Count > 0:
        name = self.GetSessionParameterName(Sess)
        if len(name) > 0:
          if Sess.Request.Cookie.Has(name):
            session_cookie_found = False
            for sc in Sess.Response.SetCookies:
              if sc.Name == name:
                session_cookie_found = True
                if sc.Value == Sess.Request.Cookie.Get(name):
                  Summary = "The value of the Session ID is the same after what appears to be an authentication attempt by the user. If this was a successful login and the Session IDs are stored in cookies then this application is affected by Session Fixation vulnerability."
                  RequestTrigger = "{0}={1}".format(sc.Name, sc.Value)
                  ResponseTrigger = "{0}={1}".format(sc.Name, sc.Value)
                  RequestTriggerDesc = "The the cookie parameter '{0}' appears to contain the session ID value. If this is the login request then the pre-authenticated session ID value is '{1}'".format(sc.Name, sc.Value)
                  ResponseTriggerDesc = "The Session ID value being set in the Set-Cookie header for the parameter '{0}' is the same as the one found in the request. This indicates that the session ID value is not changing after authentication.".format(sc.Name)
                  self.ReportSessionFixation(Summary, RequestTrigger, RequestTriggerDesc, ResponseTrigger, ResponseTriggerDesc, FindingConfidence.Low, FindingSeverity.Medium)
            if not session_cookie_found:
              Summary = "The value of the Session ID is the same after what appears to be an authentication attempt by the user. If this was a successful login and the Session IDs are stored in cookies then this application is affected by Session Fixation vulnerability."
              RequestTrigger = "{0}={1}".format(name, Sess.Request.Cookie.Get(name))
              ResponseTrigger = ""
              RequestTriggerDesc = "The the cookie parameter '{0}' appears to contain the session ID value. If this is the login request then the pre-authenticated session ID value is '{1}'".format(name, Sess.Request.Cookie.Get(name))
              ResponseTriggerDesc = "The response does not contain any Set-Cookie headers that sets a new value for the Cookie parameter '{0}'. This indicates that the session ID value is not changing after authentication.".format(name)
              self.ReportSessionFixation(Summary, RequestTrigger, RequestTriggerDesc, ResponseTrigger, ResponseTriggerDesc, FindingConfidence.Low, FindingSeverity.Medium)

  def IsLoginRequest(self, Req):
    login_url_keywords = ['login','auth','signin','signoff']
    login_usernames = ['uname','username','email','id','user','uid','user_name']
    login_passwords = ['pwd','password','pass','passwd','passw']
    
    url_check_pass = False
    username_check_pass = False
    password_check_pass = False
    
    username_in_url = False
    password_in_url = False
    
    username_parameter = ""
    password_parameter = ""
    
    for word in login_url_keywords:
      if(re.search(word, Req.Url, re.I)):
        url_check_pass = True
        break
    
    for word in login_usernames:
      for param in Req.Body.GetNames():
        if word == param.lower():
          username_check_pass = True
          username_parameter = word
          break
    
    for word in login_passwords:
      for param in Req.Body.GetNames():
        if word == param.lower():
          password_check_pass = True
          password_parameter = word
          break
        
    if(not username_check_pass):
      for word in login_usernames:
        for param in Req.Query.GetNames():
          if word == param.lower():
            username_check_pass = True
            username_parameter = word
            username_in_url = True
            break
    
    if(not password_check_pass):
      for word in login_passwords:
        for param in Req.Query.GetNames():
          if word == param.lower():
            password_check_pass = True
            password_parameter = word
            password_in_url = True
            break
    
    if((url_check_pass and username_check_pass) or password_check_pass):
      if(password_in_url):
        Summary = "The application sends the user's password in clear-text over the URL."
        if(username_in_url and (Req.Method == "GET")):
          self.ReportPasswordInUrl(Summary, password_parameter, "", FindingConfidence.High, FindingSeverity.Medium)
        elif(Req.Method == "GET"):
          self.ReportPasswordInUrl(Summary, password_parameter, "", FindingConfidence.Medium, FindingSeverity.Medium)
        else:
          self.ReportPasswordInUrl(Summary, password_parameter, "", FindingConfidence.Low, FindingSeverity.Medium)
      return True
    else:
      return False

  def GetSessionParameterName(self, Sess):
    for sc in Sess.Response.SetCookies:
      if sc.Name.lower().count("session") > 0:
        return sc.Name
    for name in Sess.Request.Cookie.GetNames():
      if name.lower().count("session") > 0:
        return name
    return ""
        
         
  def ReportSessionFixation(self, Summary, RequestTrigger, RequestTriggerDesc, ResponseTrigger, ResponseTriggerDesc, Confidence, Severity):
    #Results = ThreadStore.Get("Results")
    #Sess = ThreadStore.Get("Session")
    Signature = 'SessionFixation|{0}|{1}|{2}'.format(self.MakeUniqueString(self.Sess), RequestTrigger, ResponseTrigger)
    if self.ReportAll or self.IsSignatureUnique(self.Sess.Request.BaseUrl, FindingType.Vulnerability, Signature):
      PR = Finding(self.Sess.Request.BaseUrl)
      PR.Title = "Session Fixation Found"
      PR.Summary = Summary
      PR.Triggers.Add(RequestTrigger, RequestTriggerDesc, self.Sess.Request, ResponseTrigger, ResponseTriggerDesc, self.Sess.Response)
      PR.Signature = Signature
      PR.Confidence = Confidence
      PR.Severity = Severity
      self.Results.Add(PR)
    
  def ReportPasswordInUrl(self, Summary, RequestTrigger, ResponseTrigger, Confidence, Severity):
    #Results = ThreadStore.Get("Results")
    #Sess = ThreadStore.Get("Session")
    Signature = 'PasswordInUrl|{0}|{1}|{2}'.format(self.MakeUniqueString(self.Sess), RequestTrigger, ResponseTrigger)
    if self.ReportAll or self.IsSignatureUnique(self.Sess.Request.BaseUrl, FindingType.Vulnerability, Signature):
      PR = Finding(self.Sess.Request.BaseUrl)
      PR.Title = "Password Sent in URL"
      PR.Summary = Summary
      PR.Triggers.Add(RequestTrigger, "Parameter name '{0}' was found in the Query, this looks like a field containing password".format(RequestTrigger), self.Sess.Request, ResponseTrigger, "", self.Sess.Response)
      PR.Signature = Signature
      PR.Confidence = Confidence
      PR.Severity = Severity
      self.Results.Add(PR)

  def MakeUniqueString(self, Sess):
    us = '{0}|{1}:'.format(Sess.Request.SSL.ToString(), Sess.Request.Method)
    return us

p = SessionAnalysis()
PassivePlugin.Add(p.GetInstance())

