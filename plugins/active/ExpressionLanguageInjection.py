#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
import re


class ExpressionLanguageInjection(ActivePlugin):


  def GetInstance(self):
    p = ExpressionLanguageInjection()
    p.Name = 'Expression Language Injection'
    p.Description = 'Active plugin to check for Expression Language injection'
    p.Version = '0.1'
    return p


  def Check(self, scnr):
    self.scnr = scnr
    self.RequestTriggers = []
    self.ResponseTriggers = []
    self.RequestTriggerDescs = []
    self.ResponseTriggerDescs = []
    self.TriggerRequests = []
    self.TriggerResponses = []
    self.TriggerCount = 0
    self.reasons = []
    self.CheckForELI()
    self.AnalyzeTestResult()


  def CheckForELI(self):   
    self.scnr.Trace("<i<br>><i<h>>Checking for Expression Langugage Injection:<i</h>>")
    for i in range(2):
      add_num_1 = 0
      add_num_2 = 0
      base_res = self.scnr.BaseResponse
      found_rand_nums = False
      while(not found_rand_nums):
        add_num_1 = Tools.GetRandomNumber(1000000, 10000000)
        add_num_2 = Tools.GetRandomNumber(1000000, 10000000)
        if base_res.BodyString.count(str(add_num_1 + add_num_2)) == 0:
          found_rand_nums = True
    
      add_str = "{0}+{1}".format(str(add_num_1), str(add_num_2))
      added_str = str(add_num_1 + add_num_2)
      
      payload = "${{{0}}}".format(add_str)
      self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
      res = self.scnr.Inject(payload)
      if res.BodyString.count(added_str) > 0:
        if i == 0:
          self.scnr.ResponseTrace("    ==> <i<b>>Got {0} in the response, this is the result of executing '{1}'. Rechecking to confirm.<i</b>>".format(added_str, add_str))
          continue
        else:
          self.scnr.ResponseTrace("    ==> <i<cr>>Got {0} in the response, this is the result of executing '{1}'. Indicates Expression Language Injection!<i</cr>>".format(added_str, add_str))
          self.scnr.SetTraceTitle("Expression Language Injection", 5)
          self.AddToTriggers(payload, "The payload in this request contains a Expression Language snippet which if executed will add the numbers {0} & {1} and print the result. The Expression Language snippet is: {2}".format(add_num_1, add_num_2, payload), added_str, "This response contains the value {0} which is the sum of the numbers {1} & {2} which were sent in the request.".format(add_num_1 + add_num_2, add_num_1, add_num_2))
          reason = self.GetEchoReason(payload, payload, add_num_1, add_num_2)
          self.reasons.append(reason)
          return
      else:
        if i == 0:
          self.scnr.ResponseTrace("    ==> Did not get {0} in the response".format(added_str))
          self.scnr.Trace("<i<br>>No indication for presence of Expression Language Injection")
          break
        else:
          self.scnr.ResponseTrace("    ==> Did not get {0} in the response. The last instance might have been a false trigger.".format(added_str))
          self.scnr.Trace("<i<br>>No indication for presence of Expression Language Injection")

  
  def AddToTriggers(self, RequestTrigger, RequestTriggerDesc, ResponseTrigger, ResponseTriggerDesc):
    self.RequestTriggers.append(RequestTrigger)
    self.ResponseTriggers.append(ResponseTrigger)
    self.RequestTriggerDescs.append(RequestTriggerDesc)
    self.ResponseTriggerDescs.append(ResponseTriggerDesc)
    self.TriggerRequests.append(self.scnr.InjectedRequest.GetClone())
    self.TriggerResponses.append(self.scnr.InjectionResponse.GetClone())
    self.TriggerCount = self.TriggerCount + 1
  
  def AnalyzeTestResult(self):
    if len(self.RequestTriggers) > 0:
      self.ReportELInjection(FindingConfidence.Medium)
  
  def ReportELInjection(self, confidence):
    self.scnr.SetTraceTitle("Expression Language Injection Found", 10)
    pr = Finding(self.scnr.InjectedRequest.BaseUrl)
    pr.Title = "Expression Language Injection Found"
    pr.Summary = "Expression Language Injection been detected in the '{0}' parameter of the {1} section of the request.<i<br>><i<br>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.GetSummary())
    for reason in self.reasons:
      pr.AddReason(reason)
    for i in range(len(self.RequestTriggers)):
      pr.Triggers.Add(self.RequestTriggers[i], self.RequestTriggerDescs[i], self.TriggerRequests[i], self.ResponseTriggers[i], self.ResponseTriggerDescs[i], self.TriggerResponses[i])
    pr.Type = FindingType.Vulnerability
    pr.Severity = FindingSeverity.High
    pr.Confidence = confidence
    self.scnr.AddFinding(pr)

  def GetSummary(self):
    Summary = "Expression Language Injection is an issue where it is possible to inject and execute code on the server-side. For more details on this issue refer <i<cb>>https://www.owasp.org/index.php/Expression_Language_Injection<i</cb>><i<br>><i<br>>"
    return Summary
  
  def GetEchoReason(self, payload, code, num_a, num_b):
    Reason = "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application. This payload has a small Expression Language snippet - <i<hlg>>{1}<i</hlg>>. ".format(payload, code)
    Reason = Reason + "If this code is executed then <i<hlg>>{0}<i</hlg>> and <i<hlg>>{1}<i</hlg>> will be added together and the sum of the addition will be printed back in the response. ".format(num_a, num_b)
    Reason = Reason + "The response that came back from the application after the payload was injected had the value <i<hlg>>{0}<i</hlg>>, which is the sum of <i<hlg>>{1}<i</hlg>> & <i<hlg>>{2}<i</hlg>>. ".format(num_a + num_b, num_a, num_b)
    Reason = Reason + "This indicates that the injected code snippet could have been executed on the server-side."
    
    ReasonType = "Error"
    
    #False Positive Check
    FalsePositiveCheck = "To check if this was a valid case or a false positive you can manually inject the same payload but by changing the two numbers to some other value. Then you can observe if the response contains the sum of two numbers."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, self.TriggerCount, FalsePositiveCheck)
    return FR

p = ExpressionLanguageInjection()
ActivePlugin.Add(p.GetInstance())
