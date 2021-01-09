#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license
from IronWASP import *
from System import *
import clr

#Inherit from the base ActivePlugin class
class HeaderInjection(ActivePlugin):
  
  crlf_inj_str = ["\r\nNeww: Headerr", "aa\r\nNeww: Headerr", "\r\nNeww: Headerr\r\n", "aa\r\nNeww: Headerr\r\n"]
  
  def GetInstance(self):
    p = HeaderInjection()
    p.Name = "Header Injection"
    p.Description = "Active plugin that checks for HTTP Header Injection by inserting CR LF characters"
    p.Version = "0.4"
    return p
  
  #Override the Check method of the base class with custom functionlity
  def Check(self, scnr):
    self.scnr = scnr
    self.reason = ""
    self.CheckForCRLFInjection()
  
  def CheckForCRLFInjection(self):
    self.scnr.Trace("<i<br>><i<h>>Checking for Header Injection:<i</h>>")
    self.scnr.Trace("<i<br>><i<b>>  Trying to inject a header named 'Neww'<i</b>>")
    crlf_inj_found = False
    prefix = ["", self.scnr.PreInjectionParameterValue]
    for cis in self.crlf_inj_str:
      if crlf_inj_found:
        break
      for p in prefix:
        payload = p + cis
        self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
        res = self.scnr.Inject(payload)
        if(res.Headers.Has("Neww")):
          self.scnr.ResponseTrace("  ==> <i<cr>>Header 'Neww' injected<i</cr>>")
          self.reason = self.GetReason(payload)
          self.ReportCRLFInjection(payload, "The payload in this request attempts to insert a header with name 'Neww' in the response. The payload is {0}".format(payload), "Neww: Headerr", "This response has a header named 'Neww' which was added because of the payload")
          crlf_inj_found = True
          break
        else:
          self.scnr.ResponseTrace("  ==> Header not injected")
  
  def ReportCRLFInjection(self, req_trigger, req_trigger_desc, res_trigger, res_trigger_desc):
    self.scnr.SetTraceTitle("Header Injection Found", 10)
    pr = Finding(self.scnr.InjectedRequest.BaseUrl)
    pr.Title = "Header Injection Found"
    pr.Summary = "Header Injection has been detected in the '{0}' parameter of the {1} section of the request.<i<br>><i<br>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.GetSummary())
    pr.AddReason(self.reason)
    pr.Triggers.Add(req_trigger, req_trigger_desc, self.scnr.InjectedRequest, res_trigger, res_trigger_desc, self.scnr.InjectionResponse)
    pr.Type = FindingType.Vulnerability
    pr.Severity = FindingSeverity.High
    pr.Confidence = FindingConfidence.High
    self.scnr.AddFinding(pr)

  def GetSummary(self):
    Summary = "Header Injection is an issue where it is possible to inject a new HTTP Header in the response from the application. For more details on this issue refer <i<cb>>http://en.wikipedia.org/wiki/HTTP_header_injection<i</cb>><i<br>><i<br>>"
    return Summary

  def GetReason(self, payload):
    payload = Tools.EncodeForTrace(payload)
    
    #Reason = "IronWASP sent <i>'\r\nNeww: Headerr</i> as payload to the application. This payload has CRLF characters followed by the string <i>Neww: Headerr</i> which is in the format of a HTTP Header with name <i>Neww</i> and value <i>Headerr</i>. "
    Reason = "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application. This payload has CRLF characters followed by the string <i<hlg>>Neww: Headerr<i</hlg>> which is in the format of a HTTP Header with name <i<hlg>>Neww<i</hlg>> and value <i<hlg>>Headerr<i</hlg>>. ".format(payload)
    Reason = Reason + "The response that came back from the application after injecting this payload has an HTTP header named <i<hlg>>Neww<i</hlg>>. "
    Reason = Reason + "This indicates that our payload caused an HTTP header to be injected in the response."
        
    ReasonType = "HeaderAdded"
    
    #False Positive Check
    FalsePositiveCheck = "To check if this was a valid case or a false positive you can send the same payload but with different values for the header name part of the payload. If the response contains any HTTP headers with the specified names then there actually is Header Injection."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, 1, FalsePositiveCheck)
    return FR


p = HeaderInjection()
ActivePlugin.Add(p.GetInstance())
