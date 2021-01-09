import clr
clr.AddReference("System")
clr.AddReference("System.Data")
clr.AddReference("System.Data.SQLite")

import System
from System.Data.SQLite import *
from IronWASP import *
import re
import db as db2
import webservices as ws 


class fingerprint:
    
  def page301(self):
    
    if len(self.page301list)>0:
      for x in self.page301list:
        sess = Session.FromLog(x,"IronSAP")
        req = sess.Request
        resp = sess.Response
        headers = resp.Headers
        if self.isap.verbose:
          print headers.Get("Location"),"\n",
        
  def checkpages2(self):
    #This is the call to the web services Module
    ws1 = ws.webservices(self.val,self.isap)
    #Tools.Trace("fingerprint.py","checkll   pages 2")
    ws1.start()

          
  def loginbypass(self,session,username):
    req = session.Request
    resp = session.Response
    c = CookieStore()
    response = Crawler.GetFormSubmissions(req, resp, c)
    header = response[0].Headers
    header.Set("REMOTE_USER",username)
    resp1 = response[0].Send()
    resphtml = resp1.Html
    #print resphtml.Get("script","src","/irj/portalapps/com.sap.portal.runtime.logon/js/basic.js")
    val = len(resphtml.Get("script","src","/irj/portalapps/com.sap.portal.runtime.logon/js/basic.js"))
    if val==0:
      pr = Finding(session.Request.Host)
      pr.Title = "SAP Login Bypass Possible"
      pr.Summary = "SAP Web Login bypass could be possible with Header Inclusion attack -- SAP Active Directory Authtenction in use."
      pr.Plugin = " "
      pr.Triggers.Add(resp1.Headers.Get("REMOTE_USER"),response[0],"",resp1)
      g = FindingSeverity.High
      h = FindingConfidence.High
      pr.Severity = g
      pr.Confidence =h
      pr.Report()
    else:
      self.isap.print_out("Remote Authentication did not work."+"\n", 1)

    
  def checkpages(self):
    #Tools.Trace("fingerprint.py","CheckPages Start")
    urlist = ["/mmr/MMR","/sap/public/info","/run/build_info.jsp","/rep/build_info.html","/sap/admin/public/index.html","/irj/portal"]
    if len(self.page200list)>0:
      #print "Performing Analysis of Pages that has been found...."
      for req in self.page200list:
        sess = Session.FromLog(req,"IronSAP")
        #Tools.Trace("fingerprint.py",str(sess))
        if self.isap.perform_attack:
          req = sess.Request
          scan = Scanner(req)
          scan.CheckAll()
          scan.InjectAll()
          scan.LaunchScan()
        requrl = sess.Request.UrlPath
        for url in urlist:
          if requrl==url:
            if requrl == "/irj/portal":
              self.isap.print_out("Attempting to Bypass the Login using Additional Header\n", 1)
              usernames = ["Administrator","Admin"]
              for username in usernames:
                self.isap.print_out( "Trying to login with username: "+username+"\n", 1)
                self.loginbypass(sess,username)
            if requrl=="/sap/admin/public/index.html":
              #self.pagecheckerlist.append(sess.Request.FullUrl+" "+"==>"+" SAP Web Administration Interface")
              pr = Finding(sess.Request.Host)
              pr.Title = "SAP Web Administration Interface"
              pr.Summary = "Web Administration Interface could leak some sensitive information."
              pr.Plugin = " "
              pr.Triggers.Add('Administration',sess.Request,"",sess.Response)
              g = FindingSeverity.Medium
              h = FindingConfidence.High
              pr.Severity = g
              pr.Confidence =h
              pr.Report()
            if requrl=="/sap/public/info":
              pr = Finding(sess.Request.Host)
              pr.Title = "The Info Service"
              pr.Summary = "Discloses sensitive information of the SAP infrastructure"
              pr.Plugin = " "
              pr.Triggers.Add('Info Service',sess.Request,"",sess.Response)
              g = FindingSeverity.High
              h = FindingConfidence.High
              pr.Severity = g
              pr.Confidence =h
              pr.Report()
    #print self.page301list,"301 List"
    #Tools.Trace("fingerprint.py","calling Web Service")
    self.checkpages2()
    
  
  def resultstorer(self,type,value):
    if type=="page401":
      lens = len(self.page401res)
      self.page401res[lens+1]=value
    if type=="page200":
      lens = len(self.page200res)
      self.page200res[lens+1]=value
    if type=="page404":
      lens = len(self.error404res)
      self.error404res[lens+1]=value
      
  def page401(self):
    #Tools.Trace("fingerprint.py","page401 - start")
    #print " I am in here "
    if len(self.page401list)>0:
      #print len(self.page401list)
      for req in self.page401list:
        sess = Session.FromLog(req,"IronSAP")
        requrl = sess.Request.FullUrl
        req1 = Request("HEAD",requrl)
        resp = req1.Send()
        #print resp.ToString(),req1.FullUrl
        if resp.Code==200:
          pr = Finding(sess.Request.Host)
          pr.Title = "Possible VERB Tampering"
          pr.Summary = "Resources that are protected with login could be accessed by changing the HTTP Request Method."
          pr.Plugin = " "
          pr.Triggers.Add("",req1,"",resp)
          g = FindingSeverity.High
          h = FindingConfidence.High
          pr.Severity = g
          pr.Confidence =h
          pr.Report()
          self.resultstorer("page401",[req1.FullUrl,resp.ToString()])
    #Tools.Trace("fingerprint.py","page401 - end")
    self.resultcounter()
    
    
  def resultcounter(self):
    self.respcounter=self.respcounter+1
    if self.respcounter==3:
      #self.resultprinter()
      self.respcounter = 0
      dbw = db2.dbwrite(self.isap)
      dbw.fingerprintwrite(self.page200res,self.error404res,self.page401res,self.val)
      #Tools.Trace("fingerprint.py","resultcounter")
      self.checkpages()
    
  
  def resultprinter(self):
    print self.page200res
    print self.error404res
    
  
  def page404(self):
    #Tools.Trace("fingerprint.py","page404 - start")
    if len(self.page404list)>0:
      #print len(self.page404list)
      for req in self.page404list:
        sess = Session.FromLog(req,"IronSAP")
        resp = sess.Response.ToString()
        match = re.search(r"[\w\s]+_[\w\s]+_\d\d",resp)
        if match:
          result = match.group()
        else:
          result = ""
        if result!="":
          resultsz = re.split("_",result)
          pr = Finding(sess.Request.Host)
          pr.Title = "Critical Information in Page Not Found Pages"
          pr.Summary = "The Error Page for HTTP response seems to be leaking a critical infrastructure information."
          pr.Plugin = " "
          info = resultsz[0]+" "+resultsz[2]+" "+resultsz[1]
          pr.Triggers.Add(info,sess.Request,"",sess.Response)
          g = FindingSeverity.High
          h = FindingConfidence.High
          pr.Severity = g
          pr.Confidence =h
          pr.Report()
          self.resultstorer("page404",[resultsz[0],resultsz[2],resultsz[1],sess.Request.FullUrl])
    self.resultcounter()
    
  def page200(self):
    #Tools.Trace("fingerprint.py","page200 - start")
    if len(self.page200list)>0:
      for req in self.page200list:
        #Tools.Trace("page200",str(req))
        sess = Session.FromLog(req,"IronSAP") #Delete this Later... 
        #Tools.Trace("page200",str(sess))
        resp = sess.Response
        resphtml = resp.Html
        #logincheck = resphtml.Get("input","name","sap-system-login")
        if len(resphtml.Get("script","src","/irj/portalapps/com.sap.portal.runtime.logon/js/basic.js"))>0:
          self.resultstorer("page200",[sess.Request.FullUrl,"LOGIN Page"])
        else:
          #pr = Finding(sess.Request.Host)
          #pr.Title = "Interesting Pages"
          #pr.Summary = "Pages with some interesting content found.further automated analysis will be performed and mannual tests can be performed."
          #pr.Plugin = " "
          #pr.Triggers.Add("",sess.Request,"",sess.Response)
          #pr.FindingType = FindingType.TestLead
          #pr.Report()
          self.resultstorer("page200",[sess.Request.FullUrl,"Interesting  Page"])
    else:
    	pass
    self.resultcounter()
    
         
  def htmlpages(self,ports):
    self.isap.print_out("Fetching the webpages from the list .. only displaying 200 & 401 Responses. For all responses turn on Verbose mode...."+"\n", 0)
    ip = self.val["ip"]
    portlist = ports
    loc = Config.Path+"\\modules\\IronSAP\\"
    f = open(loc+"sapurl.txt")
    lines = f.readlines()
    for port in portlist:
      proto = "http://"
      try:
        Request("http://" + ip + ":" + str(port)).Send()
      except:
        try:
    	  Request("https://" + ip + ":" + str(port)).Send()
    	  proto = "https://"
    	except:
          pass
      for line in lines:
        try:
          url = proto + ip + ":" + port+line.rstrip('\r\n')
          req = Request(url)
          req.SetSource("IronSAP")
          req.Headers.Set("User-Agent","Mozilla/5.0 (Windows NT 5.1; rv:14.0) Gecko/20100101 Firefox/14.0.1")
          resp = req.Send()
          #print url,resp.Code,resp.Status,req.GetId(),"\n"
          if resp.Code==200:
            self.isap.print_out(url+str(resp.Code)+str(resp.Status)+str(req.GetId())+"\n", 2)
            self.page200list.append(req.GetId())
          elif resp.Code==401:
            self.isap.print_out(url+str(resp.Code)+str(resp.Status)+str(req.GetId())+"\n", 2)
            self.page401list.append(req.GetId())
          elif resp.Code==404:
            if self.isap.verbose:
              self.isap.print_out(url+str(resp.Code)+str(resp.Status)+str(req.GetId())+"\n", 2)
            self.page404list.append(req.GetId())
          elif resp.Code==301:
            self.page301list.append(req.GetId())
            if self.isap.verbose:
              self.isap.print_out(url+str(resp.Code)+str(resp.Status)+str(req.GetId())+"\n", 1)
          else:
            if self.isap.verbose:
              pass#self.isap.print_out(url+str(resp.Code)+str(resp.Status)+str(req.GetId())+"\n", 1)
        except:
          if self.isap.verbose:
            self.isap.print_out("Could not connect to the URL"+url, 1)
    self.isap.print_out("Pages Request Completed"+"\n", 0)
    self.sleeper()
  

  def fpcontroller(self):
    self.isap.print_out("Starting HTTP Responses Analysis ....", 0)
    if len(self.page200list) != 0:
    	IronThread.Run(self.page200)
    else:
    	self.respcounter = self.respcounter+1
    if len(self.page404list) != 0:
    	IronThread.Run(self.page404)
    else:
    	self.respcounter = self.respcounter+1
    if len(self.page401list)!= 0:
    	IronThread.Run(self.page401)
    else:
    	self.respcounter = self.respcounter+1
    #Tools.Trace("fingerprint.py","fpcontroller - end")
    #IronThread.Run(self.page301)
    


  def sleeper1(self):
    IronThread.Sleep(5000)
    self.fpcontroller()
    
  def sleeper(self):
    IronThread.Run(self.sleeper1)
    
  def __init__(self,values,isap):
    self.isap = isap
    self.val = values
    self.page200list = []
    self.page404list = []
    self.page301list = []
    self.page401list = []
    self.error404res  = {}
    self.page200res = {}
    self.page401res={}
    self.respcounter = 0
    self.pagecheckerlist=[]

  def starts(self):
    httpports = []
    f = open("ports.txt","a")
    for port in self.val["HTTP Services"]:
      httpports.append(str(port))
    for port in self.val["Message Server HTTP"]:
      httpports.append(str(port))
    for port in self.val["ICM HTTP"]:
      httpports.append(str(port))
    for port in self.val["JAVA HTTP"]:
      httpports.append(str(port))
    
    if len(httpports) > 0:
        self.isap.print_out("\r\nHTTP Ports detected are:"+"\n", 0)
        for port in httpports:
            self.isap.print_out(str(port), 0)
        self.htmlpages(httpports)
    else:
        self.isap.print_out("\r\nNo HTTP ports dectected. Cannot proceed further.", 0)
        self.isap.stopper()
	