#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license
from IronWASP import *
from System import *
import clr
import re


#Inherit from the base ActivePlugin class
class CodeInjection(ActivePlugin):
  def GetInstance(self):
    p = CodeInjection()
    p.Name = "Code Injection"
    p.Description = "Active Plugin to check for CodeInjection vulnerability"
    p.Version = "0.4"
    return p
  
  #Check logic based on https://github.com/Zapotek/arachni/blob/master/modules/audit/code_injection.rb of the Arachni project
  #Override the Check method of the base class with custom functionlity
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
    self.CheckForCodeInjection()
  
  def CheckForCodeInjection(self):
    self.scnr.Trace("<i<br>><i<h>>Checking for Code Injection:<i</h>>")
    self.CheckForEchoBasedCodeInjection()
    self.CheckForTimeBasedCodeInjection()
    self.AnalyzeTestResult()
  
  def CheckForEchoBasedCodeInjection(self):
    #lang_order [php, perl, pyton, asp, ruby]
    functions = ['echo <add_str>;', 'print <add_str>;', 'print <add_str>', 'Response.Write(<add_str>)', "puts <add_str>"]
    comments = ["#", "#", "#", "'", "#"]
    prefixes = ["", ";", "';", '";']
    
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
    
    self.scnr.Trace("<i<br>><i<h>>Checking for Echo based Code Injection:<i</h>>")
    for i in range(len(functions)):
      for p in prefixes:
        inj_comments = ["", comments[i]]
        for c in inj_comments:
          func_to_execute = functions[i].replace("<add_str>", add_str)
          payload = "{0}{1}{2}".format(p, func_to_execute, c)
          self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
          res = self.scnr.Inject(payload)
          if res.BodyString.count(added_str) > 0:
            self.scnr.ResponseTrace("    ==> <i<cr>>Got {0} in the response, this is the result of executing '{1}'. Indicates Code Injection!<i</cr>>".format(added_str, add_str))
            self.scnr.SetTraceTitle("Echo based Code Injection", 5)
            self.AddToTriggers(payload, "The payload in this request contains a code snippet which if executed will add the numbers {0} & {1} and print the result. The code snippet is: {2}".format(add_num_1, add_num_2, func_to_execute), added_str, "This response contains the value {0} which is the sum of the numbers {1} & {2} which were sent in the request.".format(add_num_1 + add_num_2, add_num_1, add_num_2))
            reason = self.GetErrorReason(payload, func_to_execute, add_num_1, add_num_2)
            self.reasons.append(reason)
            return
          else:
            self.scnr.ResponseTrace("    ==> Did not get {0} in the response".format(added_str))
  
  def CheckForTimeBasedCodeInjection(self):
    self.scnr.Trace("<i<br>><i<h>>Checking for Time based Code Injection:<i</h>>")
    #set the time related values for time-based code injection check
    self.time = 0
    max_delay = 0
    min_delay = -1
    self.scnr.Trace("<i<br>>Sending three requests to get a baseline of the response time for time based check:")
    base_line_delays = []
    avg_delay = 0
    for i in range(3):
      res = self.scnr.Inject()
      avg_delay = avg_delay + res.RoundTrip
      base_line_delays.append("  {0}) Response time is - {1} ms".format(i+1, res.RoundTrip))
      if res.RoundTrip > max_delay:
        max_delay = res.RoundTrip
      if res.RoundTrip < min_delay or min_delay == -1:
        min_delay = res.RoundTrip
    avg_delay = avg_delay / 3
    
    self.scnr.Trace("<i<br>>".join(base_line_delays))
    if min_delay > 5000:
      self.time = ((max_delay + min_delay) / 1000) + 1
    else:
      self.time = ((max_delay + 5000) / 1000) + 1
    self.scnr.Trace("<i<br>>Maximum Response Time: {0}ms. Minimum Response Time: {1}ms<i<br>>Induced Time Delay will be for {2}ms<i<br>>".format(max_delay, min_delay, self.time * 1000))
    
    functions = ['sleep(<seconds>);', 'import time;time.sleep(<seconds>);']
    prefixes = ["", "';", '";']
    comments = ["", "#"]
    for f in functions:
      for p in prefixes:
        for c in comments:
          func_to_execute = f.replace("<seconds>", str(self.time))
          payload = "{0}{1}{2}".format(p, func_to_execute, c)
          self.SendAndAnalyzeTimePayload(payload, func_to_execute, avg_delay)
  
  def SendAndAnalyzeTimePayload(self, payload, func_to_execute, avg_time):
    for i in range(2):
      self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
      res = self.scnr.Inject(payload)
      #we reduce the delay by 3 seconds to make up for the the fact that the ping could complete earlier
      if res.RoundTrip >= self.time * 1000:
        if i == 0:
          self.scnr.ResponseTrace("    ==> <i<b>>Observed a delay of {0}ms, induced delay was for {1}ms. Rechecking the delay by sending the same payload again<i</b>>".format(res.RoundTrip, self.time * 1000))
        else:
          self.scnr.ResponseTrace("    ==> <i<cr>>Observed a delay of {0}ms, induced delay was for {1}ms. Delay observed twice, indicates Code Injection!!<i</cr>>".format(res.RoundTrip, self.time * 1000))
          self.AddToTriggers(payload, "The payload in this request contains a code snippet which if executed will cause the response to be delayed by {0} milliseconds. The code snippet is: {1}".format(self.time * 1000, func_to_execute), "", "It took {0}milliseconds to recieve the response from the server. It took so long because of the {1} millisecond delay caused by the payload.".format(res.RoundTrip, self.time * 1000))
          reason = self.GetBlindReason(payload, func_to_execute, res.RoundTrip, avg_time)
          self.reasons.append(reason)
      else:
        if i == 0:
          self.scnr.ResponseTrace("    ==> Response time was {0}ms. No delay observed.".format(res.RoundTrip))
          return
        else:
          self.scnr.ResponseTrace("    ==> Response time was {0}ms. Delay did not reoccur, initial delay could have been due to network issues.".format(res.RoundTrip))
  
  def AddToTriggers(self, RequestTrigger, RequestTriggerDesc, ResponseTrigger, ResponseTriggerDesc):
    self.RequestTriggers.append(RequestTrigger)
    self.ResponseTriggers.append(ResponseTrigger)
    self.RequestTriggerDescs.append(RequestTriggerDesc)
    self.ResponseTriggerDescs.append(ResponseTriggerDesc)
    self.TriggerRequests.append(self.scnr.InjectedRequest.GetClone())
    self.TriggerResponses.append(self.scnr.InjectionResponse.GetClone())
    self.TriggerCount = self.TriggerCount + 1
  
  def AnalyzeTestResult(self):
    if len(self.RequestTriggers) == 1:
      self.ReportCodeInjection(FindingConfidence.Medium)
    elif len(self.RequestTriggers) > 1:
      self.ReportCodeInjection(FindingConfidence.High)
  
  def ReportCodeInjection(self, confidence):
    self.scnr.SetTraceTitle("Code Injection Found", 10)
    pr = Finding(self.scnr.InjectedRequest.BaseUrl)
    pr.Title = "Code Injection Found"
    pr.Summary = "Code Injection been detected in the '{0}' parameter of the {1} section of the request.<i<br>><i<br>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.GetSummary())
    for reason in self.reasons:
      pr.AddReason(reason)
    for i in range(len(self.RequestTriggers)):
      pr.Triggers.Add(self.RequestTriggers[i], self.RequestTriggerDescs[i], self.TriggerRequests[i], self.ResponseTriggers[i], self.ResponseTriggerDescs[i], self.TriggerResponses[i])
    pr.Type = FindingType.Vulnerability
    pr.Severity = FindingSeverity.High
    pr.Confidence = confidence
    self.scnr.AddFinding(pr)

  def GetSummary(self):
    Summary = "Code Injection is an issue where it is possible to inject and execute code on the server-side. For more details on this issue refer <i<cb>>https://www.owasp.org/index.php/Code_Injection<i</cb>><i<br>><i<br>>"
    return Summary
  
  def GetErrorReason(self, payload, code, num_a, num_b):
    #payload - ';print 1234 + 7678;#
    #code - print 1234 + 7678
    #num_a - 1234
    #num_b - 7678
    #Reason = "IronWASP sent <i<hlg>>';print 1234 + 7678;#<i</hlg>> as payload to the application. This payload has a small snippet of code - <i<hlg>>print 1234 + 7678<i</hlg>>. "
    Reason = "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application. This payload has a small snippet of code - <i<hlg>>{1}<i</hlg>>. ".format(payload, code)
    Reason = Reason + "If this code is executed then <i<hlg>>{0}<i</hlg>> and <i<hlg>>{1}<i</hlg>> will be added together and the sum of the addition will be printed back in the response. ".format(num_a, num_b)
    #Reason = Reason + "The response that came back from the application after the payload was injected had the value <i>34345</i>, which is the sum of 1234 & 7678. This indicates that the injected code snippet could have been executed on the server-side."
    Reason = Reason + "The response that came back from the application after the payload was injected had the value <i<hlg>>{0}<i</hlg>>, which is the sum of <i<hlg>>{1}<i</hlg>> & <i<hlg>>{2}<i</hlg>>. ".format(num_a + num_b, num_a, num_b)
    Reason = Reason + "This indicates that the injected code snippet could have been executed on the server-side."
    
    ReasonType = "Error"
    
    #False Positive Check
    FalsePositiveCheck = "To check if this was a valid case or a false positive you can manually inject the same payload but by changing the two numbers to some other value. Then you can observe if the response contains the sum of two numbers."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, self.TriggerCount, FalsePositiveCheck)
    return FR

  def GetBlindReason(self, payload, code, delayed_time, normal_time):
    #Reason = "IronWASP sent <i>';sleep(5);#</i> as payload to the application. This payload has a small snippet of code - <i>sleep(5)</i>. "
    Reason = "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application. This payload has a small snippet of code - <i<hlg>>{1}<i</hlg>>. ".format(payload, code)
    Reason = Reason + "If this code is executed then the application will return the response <i<hlg>>{0}<i</hlg>> milliseconds later than usual. ".format(self.time * 1000)
    #Reason = Reason + "After the payload was injected the response from the application took <i>6783</i> milliseconds. "
    Reason = Reason + "After the payload was injected the response from the application took <i<hlg>>{0}<i</hlg>> milliseconds. ".format(delayed_time)
    #Reason = Reason + "Normally this particular request is processed at around <i>463</i> milliseconds. "
    Reason = Reason + "Normally this particular request is processed at around <i<hlg>>{0}<i</hlg>> milliseconds. ".format(normal_time)
    Reason = Reason + "This indicates that the injected code snippet could have been executed on the server-side."
    
    ReasonType = "Blind"
    
    #False Positive Check
    FalsePositiveCheck = "To check if this was a valid case or a false positive you can manually inject the same payload but by changing the number of seconds of delay to different values. Then you can observe if the time taken for the response to be returned is affected accordingly."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, self.TriggerCount, FalsePositiveCheck)
    return FR


p = CodeInjection()
ActivePlugin.Add(p.GetInstance())
