#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license
from IronWASP import *
from System import *
import clr
#Inherit from the base ActivePlugin class
class XPATHInjection(ActivePlugin):
  error_strings = []
  
  def GetInstance(self):
    p = XPATHInjection()
    p.Name = "XPATH Injection"
    p.Description = "Active plugin that checks for XPATH Injection"
    p.Version = "0.4"
    return p
  
  #Override the Check method of the base class with custom functionlity
  def Check(self, scnr):
    self.scnr = scnr
    self.reason = ""
    self.CheckForXPATHInjection()
  
  def CheckForXPATHInjection(self):
    self.scnr.Trace("<i<br>><i<h>>Checking for XPATH Injection:<i</h>>")
    payload = "<!--'\"a"
    self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
    res = self.scnr.Inject(payload)
    errors_found = []
    for error in self.error_strings:
      if res.BodyString.count(error) > 0:
        errors_found.append(error)
    if len(errors_found) > 0:
      self.scnr.ResponseTrace("    ==> <i<cr>>XPATH Injection Found.<i<br>>Errors:<i<br>>{0}<i</cr>>".format("<i<br>>".join(errors_found)))
      self.reason = self.GetReason(payload, errors_found)
      self.ReportXPATHInjection(payload, "The payload in this request is meant to trigger XPATH errors. The payload is: {0}".format(payload), "\r\n".join(errors_found), "This response contains XPATH error messages due to the error triggered by the payload")
    else:
      self.scnr.ResponseTrace("    ==> No Errors Found")
  
  def ReportXPATHInjection(self, req_trigger, req_trigger_desc, res_trigger, res_trigger_desc):
    self.scnr.SetTraceTitle("XPATH Injection Found", 10)
    pr = Finding(self.scnr.InjectedRequest.BaseUrl)
    pr.Title = "XPATH Injection Found"
    pr.Summary = "XPATH Injection has been detected in the '{0}' parameter of the {1} section of the request.<i<br>><i<br>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.GetSummary())
    pr.AddReason(self.reason)
    pr.Triggers.Add(req_trigger, req_trigger_desc, self.scnr.InjectedRequest, res_trigger, res_trigger_desc, self.scnr.InjectionResponse)
    pr.Type = FindingType.Vulnerability
    pr.Severity = FindingSeverity.High
    pr.Confidence = FindingConfidence.High
    self.scnr.AddFinding(pr)

  def GetSummary(self):
    Summary = "XPATH Injection is an issue where it is possible execute XPATH queries on the XML file being referenced on the server-side. For more details on this issue refer <i<cb>>https://www.owasp.org/index.php/XPATH_Injection<i</cb>><i<br>><i<br>>"
    return Summary

  def GetReason(self, payload, errors):
    payload = Tools.EncodeForTrace(payload)

    #Reason = Reason + "IronWASP sent <i><!--'"a<i> as payload to the application, this payload would cause an exception to happen in insecure XPATH queries. ".format(payload)
    Reason = "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application, this payload would cause an exception to happen in insecure XPATH queries. ".format(payload)
    if len(errors) > 1:
      Reason = Reason + "The response from the application for this payload had the error messages:"
      for error in errors:
        Reason = Reason + "<i<br>><i<hlg>>{0}<i</hlg>>".format(error)
      Reason = Reason + "<i<br>>These error messages are usually found in XPATH query related exceptions. Therefore this issue has been reported."
    else:
      Reason = Reason + "The response from the application for this payload had the error message: <i<hlg>>{0}<i</hlg>>. ".format(errors[0])
      Reason = Reason + "This error message is usually found in XPATH query related exceptions. Therefore this issue has been reported."
    
    ReasonType = "Error"
    
    #False Positive Check
    FalsePositiveCheck = "Manually analyze the response received for the payload and confirm if the error message is actually because of some exception on the server-side. Resend the same payload but without the single or double quote and check if the error message disappears."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, 1, FalsePositiveCheck)
    return FR

  def SetUp(self):
    err_str_file = open(Config.Path + "\\plugins\\active\\xpath_error_strings.txt")
    err_str_file.readline()#Ignore the first line containing comments
    error_strings_raw = err_str_file.readlines()
    err_str_file.close()
    for err_str in error_strings_raw:
      err_str = err_str.strip()
      if len(err_str) > 0:
        self.error_strings.append(err_str)


p = XPATHInjection()
p.SetUp()
ActivePlugin.Add(p.GetInstance())
