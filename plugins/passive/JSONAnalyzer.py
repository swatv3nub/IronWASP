#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license
from IronWASP import *
import re


#Extend the PassivePlugin base class
class JSONAnalyzer(PassivePlugin):


  def GetInstance(self):
    p = JSONAnalyzer()
    p.Name = 'JSON Analyzer'
    p.Description = 'A passive plugin to analyze JSON content in HTTP responses and determine if they are vulnerable to JSON Hijacking'
    p.Version = '0.1'
    p.CallingState = PluginCallingState.Offline
    return p


  def Check(self, sess, results, report_all):
    self.sess = sess
    self.results = results
    self.report_all = report_all
    
    if sess.Request.Method == "GET" and sess.Response:
      bs = sess.Response.BodyString.strip()
      if sess.Response.IsJson and bs.startswith('[') and bs.endswith(']'):
        self.ReportJH()
      elif sess.Response.IsJavaScript:  
        if bs.endswith(";") or bs.endswith(")"):
          bs = bs.rstrip(";").strip().rstrip(")")
          if bs.count("(") > 0:
            func_start = bs.index("(")
            if Tools.IsJson(bs[func_start+1:]):
              self.ReportJP(bs[:func_start])
        
  
  def ReportJH(self):
    bs = self.sess.Response.BodyString
    sl = 5
    if len(bs) <= sl:
      sl = len(bs) - 1
    Signature = 'JSONHijacking|{0}'.format(self.MakeUniqueString(self.sess))
    
    if self.report_all or self.IsSignatureUnique(self.sess.Request.BaseUrl, FindingType.Vulnerability, Signature):
      PR = Finding(self.sess.Request.BaseUrl)
      PR.Title = "JSON Hijacking Possibility Found"
      PR.Summary = "The JSON data in this response is placed inside an array, this can lead to cross-domain leakage of this data. For more details about this vulnerability refer <i<cb>>http://haacked.com/archive/2009/06/25/json-hijacking.aspx<i</cb>>"
      PR.Triggers.Add("", "", self.sess.Request, "\r\n".join([bs[:sl], bs[len(bs)-sl:]]), "The JSON data in the response body is found inside [ and ] brackets which makes it an array element that is vulnerable to cross-domain leakage.", self.sess.Response)
      PR.Signature = Signature
      PR.Confidence = FindingConfidence.High
      PR.Severity = FindingSeverity.Medium
      self.results.Add(PR)

  def ReportJP(self, method_name):
    bs = self.sess.Response.BodyString
    sl = 5
    if len(bs) <= sl:
      sl = len(bs) - 1
    Signature = 'JSONPHijacking|{0}'.format(self.MakeUniqueString(self.sess))
    
    if self.report_all or self.IsSignatureUnique(self.sess.Request.BaseUrl, FindingType.Vulnerability, Signature):
      PR = Finding(self.sess.Request.BaseUrl)
      PR.Title = "JSON Hijacking via JSONP Found"
      PR.Summary = "The JSON data in this response is in the form of JSONP where it is found as the argument of the method named '{0}'. By design JSONP is meant to allow cross-domain leakage of the JSON data. For more details about this issue refer <i<cb>>http://en.wikipedia.org/wiki/JSONP#Security_concerns<i</cb>>".format(method_name)
      PR.Triggers.Add("", "", self.sess.Request, "{0}(".format(method_name), "The JSON data in the response body is found as an argument to the JavaScript function '{0}()'. This makes it vulnerable to cross-domain leakage.".format(method_name), self.sess.Response)
      PR.Signature = Signature
      PR.Confidence = FindingConfidence.High
      PR.Severity = FindingSeverity.Medium
      self.results.Add(PR)



  def MakeUniqueString(self, Sess):
    us = '{0}|{1}:'.format(Sess.Request.SSL.ToString(), Sess.Request.Method)
    return us

p = JSONAnalyzer()
PassivePlugin.Add(p.GetInstance())

