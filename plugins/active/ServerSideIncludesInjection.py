#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license
from IronWASP import *
import re


class ServerSideIncludesInjection(ActivePlugin):


  def GetInstance(self):
    p = ServerSideIncludesInjection()
    p.Name = 'Server Side Includes Injection'
    p.Description = 'An Active Plugin to detect Sever Side Include Injection vulnerabilities'
    p.Version = '0.1'
    return p


  def Check(self, scnr):
    #Check logic based on https://github.com/fnordbg/SSI-Scan
    self.scnr = scnr
    self.scnr.Trace("<i<br>><i<h>>Checking for Server Side Includes Injection:<i</h>><i<br>><i<br>>")
    payloads = ["{0}\"'><!--#printenv -->".format(self.scnr.PreInjectionParameterValue), "\"'><!--#printenv -->", "<!--#printenv -->"]
    for payload in payloads:
      self.scnr.RequestTrace("Injected - " + payload)
      res = self.scnr.Inject(payload)
      if "REMOTE_ADDR" and "DATE_LOCAL" and "DATE_GMT" and "DOCUMENT_URI" and "LAST_MODIFIED" in res.BodyString:
        self.scnr.ResponseTrace(" ==> <i<cr>> Got contents of Environment variables in the response body. Indicates SSI Injection.<i</cr>>")
        self.reason = self.GetReason(payload, ["REMOTE_ADDR", "DATE_LOCAL", "DATE_GMT", "DOCUMENT_URI", "LAST_MODIFIED"])
        self.ReportSSI(payload, "The payload in this request contains a SSI snippet <!--#printenv--> which if executed will print the contents of the environment variables. The payload is: {0}".format(payload),  "\r\n".join(["REMOTE_ADDR", "DATE_LOCAL", "DATE_GMT", "DOCUMENT_URI", "LAST_MODIFIED"]), "This response contains some keywords that are similar to some standard environment variable names.")
        return
      else:
        self.scnr.ResponseTrace(" ==> The response does not contain any Environment variable information.")
    self.scnr.Trace("<i<br>>No indication for presence of SSI Injection")


  def ReportSSI(self, req_trigger, req_trigger_desc, res_trigger, res_trigger_desc):
    self.scnr.SetTraceTitle("Server Side Includes Injection Found", 10)
    pr = Finding(self.scnr.InjectedRequest.BaseUrl)
    pr.Title = "Server Side Includes Injection Found"
    pr.Summary = "Server Side Includes Injection has been detected in the '{0}' parameter of the {1} section of the request.<i<br>><i<br>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.GetSummary())
    pr.AddReason(self.reason)
    pr.Triggers.Add(req_trigger, req_trigger_desc, self.scnr.InjectedRequest, res_trigger, res_trigger_desc, self.scnr.InjectionResponse)
    pr.Type = FindingType.Vulnerability
    pr.Severity = FindingSeverity.High
    pr.Confidence = FindingConfidence.High
    self.scnr.AddFinding(pr)

  def GetSummary(self):
    Summary = "Server Side Includes Injection is an issue where it is possible to code on the server-side. For more details on this issue refer <i<cb>>https://www.owasp.org/index.php/Server-Side_Includes_(SSI)_Injection<i</cb>><i<br>><i<br>>"
    return Summary

  def GetReason(self, payload, keywords):
    payload = Tools.EncodeForTrace(payload)
    Reason = "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application, this payload would display the environment variables to be printed in the response if the application is vulnerable to Server Side Includes Injection.".format(payload)
    Reason = Reason + "The response from the application for this payload had some keywords that are similar to the names of environment variables. These keywords were:"
    for keyword in keywords:
      Reason = Reason + "<i<br>><i<hlg>>{0}<i</hlg>>".format(keyword)
    Reason = Reason + "<i<br>>These words are similar to that of standard environment variable names, therefore this issue has been reported."
    
    ReasonType = "Echo"
    
    #False Positive Check
    FalsePositiveCheck = "Manually analyze the response received for the payload and confirm if it actually contains the environment variable details. Change the printenv command to some other SSI command and see if the response contains that command's output."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, 1, FalsePositiveCheck)
    return FR


p = ServerSideIncludesInjection()
ActivePlugin.Add(p.GetInstance())
