#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license
from IronWASP import *
import re


#Extend the ActivePlugin base class
class ServerSideRequestForgery(ActivePlugin):

  #Implement the GetInstance method of ActivePlugin class. This method is used to create new instances of this plugin.
  def GetInstance(self):
    p = ServerSideRequestForgery()
    p.Name = 'Server Side Request Forgery'
    p.Description = 'A plugin to discover SSRF vulnerabilities'
    p.Version = '0.1'
    return p

  #Override the Check method of the base class with custom functionlity
  def Check(self, scnr):
    self.scnr = scnr
    self.base_res = self.scnr.BaseResponse
    self.confidence = 0
    self.RequestTriggers = []
    self.ResponseTriggers = []
    self.RequestTriggerDescs = []
    self.ResponseTriggerDescs = []
    self.TriggerRequests = []
    self.TriggerResponses = []
    self.TriggerCount = 0
    self.reasons = []
    self.CheckForSSRF()
    self.AnalyzeTestResult()
  
  def CheckForSSRF(self):
    self.scnr.Trace("<i<br>><i<h>>Checking for Server Side Request Forgery:<i</h>>")
    self.scnr.Trace("<i<br>>Normal Response Code - {0}. Length -{0}".format(self.base_res.Code, self.base_res.BodyLength))
    p = ""
    first_time_pattern = ""
    second_time_pattern = ""
    strict_group_matched = False
    relaxed_group_matched = False
    
    if self.scnr.PreInjectionParameterValue.startswith("http://"):
      p = "http://"
    elif self.scnr.PreInjectionParameterValue.startswith("https://"):
      p = "https://"
    else:
      p = ""
      
    for i in range(2):
      payload_a = "{0}localhost:65555".format(p)
      self.scnr.RequestTrace("  Injected payload - {0}".format(payload_a))
      res_a = self.scnr.Inject(payload_a)
      req_a = self.scnr.InjectedRequest
      self.scnr.ResponseTrace("    ==> Got Response. Code- {0}. Length- {1}".format(res_a.Code, res_a.BodyLength))
    
      payload_a1 = "{0}localhost:1".format(p)
      self.scnr.RequestTrace("  Injected payload - {0}".format(payload_a1))
      res_a1 = self.scnr.Inject(payload_a1)
      req_a1 = self.scnr.InjectedRequest
      self.scnr.ResponseTrace("    ==> Got Response. Code- {0}. Length- {1}".format(res_a1.Code, res_a1.BodyLength))
    
      payload_b = "{0}localhost:66666".format(p)
      self.scnr.RequestTrace("  Injected payload - {0}".format(payload_b))
      res_b = self.scnr.Inject(payload_b)
      req_b = self.scnr.InjectedRequest
      self.scnr.ResponseTrace("    ==> Got Response. Code- {0}. Length- {1}".format(res_b.Code, res_b.BodyLength))
    
      payload_b1 = "{0}localhost:2".format(p)
      self.scnr.RequestTrace("  Injected payload - {0}".format(payload_b1))
      res_b1 = self.scnr.Inject(payload_b1)
      req_b1 = self.scnr.InjectedRequest
      self.scnr.ResponseTrace("    ==> Got Response. Code- {0}. Length- {1}".format(res_b1.Code, res_b1.BodyLength))
    
      self.scnr.Trace("<i<br>>Analysing the responses for patterns...")
    
      #Analyzing the responses for patterns
      sc = SimilarityChecker()
      sc.Add("a", res_a, payload_a)
      sc.Add("a1", res_a1, payload_a1)
      sc.Add("b", res_b, payload_b)
      sc.Add("b1", res_b1, payload_b1)
      sc.Check()
    
      requests = [req_a, req_a1, req_b, req_b1]
      responses = [res_a, res_a1, res_b, res_b1]
      request_trigger_descs = []
      request_trigger_descs.append("This payload points to the invalid port 65555 on localhost. The payload is {0}".format(payload_a))
      request_trigger_descs.append("This payload points to the valid port 1 on localhost. The payload is {0}".format(payload_a1))
      request_trigger_descs.append("This payload points to the invalid port 66666 on localhost. The payload is {0}".format(payload_b))
      request_trigger_descs.append("This payload points to the valid port 2 on localhost. The payload is {0}".format(payload_b1))
      response_trigger_descs = []
      response_trigger_descs.append("The contents of this response are different from the response of the next trigger but are similar to the response of the trigger after the next.")
      response_trigger_descs.append("The contents of this response are different from the response of the previous trigger but are similar to the response of the trigger after the next.")
      response_trigger_descs.append("The contents of this response are different from the response of the next trigger but are similar to the response of the trigger before the previous.")
      response_trigger_descs.append("The contents of this response are different from the response of the previous trigger but are similar to the response of the trigger before the previous.")
      request_triggers = [payload_a, payload_a1, payload_b, payload_b1]
      response_triggers = ["","","",""]
            
      if i == 0:
        for group in sc.StrictGroups:
          if group.Count == 2:
            if group.HasKey("a") and group.HasKey("b"):
              self.scnr.Trace("<i<br>><i<cr>>Responses for invalid port based payloads are similar to each other and are different from responses for valid port based payloads. Indicates presence of SSRF.<i</cr>>")
          
              reason = self.GetDiffReason([payload_a, payload_a1, payload_b, payload_b1], False, [], self.TriggerCount, len(request_triggers))
              self.reasons.append(reason)
          
              self.RequestTriggers.extend(request_triggers)
              self.ResponseTriggers.extend(response_triggers)
              self.RequestTriggerDescs.extend(request_trigger_descs)
              self.ResponseTriggerDescs.extend(response_trigger_descs)
              self.TriggerRequests.extend(requests)
              self.TriggerResponses.extend(responses)
              self.TriggerCount = self.TriggerCount + len(request_triggers)
              self.SetConfidence(2)
              strict_group_matched = True
      
        if not strict_group_matched:
          for group in sc.RelaxedGroups:
            if group.Count == 2:
              if group.HasKey("a") and group.HasKey("b"):
                self.scnr.Trace("<i<br>><i<cr>>Responses for invalid port based payloads are similar to each other and are different responses for valid port based payload. Indicates presence of SSRF.<i</cr>>")
          
                reason = self.GetDiffReason([payload_a, payload_a1, payload_b, payload_b1], False, [], self.TriggerCount, len(request_triggers))
                self.reasons.append(reason)
          
                self.RequestTriggers.extend(request_triggers)
                self.ResponseTriggers.extend(response_triggers)
                self.RequestTriggerDescs.extend(request_trigger_descs)
                self.ResponseTriggerDescs.extend(response_trigger_descs)
                self.TriggerRequests.extend(requests)
                self.TriggerResponses.extend(responses)
                self.TriggerCount = self.TriggerCount + len(request_triggers)
                self.SetConfidence(2)
                relaxed_group_matched = True
            
      res_times = [res_a.RoundTrip, res_a1.RoundTrip, res_b.RoundTrip, res_b1.RoundTrip]
      res_times.sort()
      if (res_times[2] - res_times[0] > 200) and (res_times[3] - res_times[0]  > 200) and (res_times[2] - res_times[1] > 200)  and (res_times[3] - res_times[1] > 200) and ((res_times[1] - res_times[0]) < 200) and ((res_times[3] - res_times[2]) < 200):
        
        if (res_a.RoundTrip == res_times[0] and res_b.RoundTrip == res_times[1])  or (res_a.RoundTrip == res_times[1] and res_b.RoundTrip == res_times[0]):
          if i == 0:
            first_time_pattern = "Valid>Invalid"
          else:
            second_time_pattern = "Valid>Invalid"
        elif (res_a1.RoundTrip == res_times[0] and res_b1.RoundTrip == res_times[1])  or (res_a1.RoundTrip == res_times[1] and res_b1.RoundTrip == res_times[0]):
          if i == 0:
            first_time_pattern = "Invalid>Valid"
          else:
            second_time_pattern = "Invalid>Valid"
            
      if len(first_time_pattern) > 0:
        if i == 0:
          self.scnr.Trace("<i<br>>There is a pattern in the roundtrip time of the four responses. Rechecking to confirm.<i<br>>")
          continue
        elif i == 1:
          if first_time_pattern == second_time_pattern:
            self.scnr.Trace("<i<br>><i<cr>>Response times for invalid port based payloads are similar to each other and are different from response times for valid port based payload. Indicates presence of SSRF.<i</cr>>")
            response_trigger_descs = []
            response_trigger_descs.append("This response time is different from the response time of the next trigger but is similar to the response time of the trigger after the next.")
            response_trigger_descs.append("This response time is different from the response time of the previous trigger but is similar to the response time of the trigger after the next.")
            response_trigger_descs.append("This response time is different from the response time of the next trigger but is similar to the response time of the trigger before the previous.")
            response_trigger_descs.append("This response time is different from the response time of the previous trigger but is similar to the response time of the trigger before the previous.")
          
            reason = self.GetDiffReason([payload_a, payload_a1, payload_b, payload_b1], True, [res_a.RoundTrip, res_a1.RoundTrip, res_b.RoundTrip, res_b1.RoundTrip], self.TriggerCount, len(request_triggers))
            self.reasons.append(reason)
      
            self.RequestTriggers.extend(request_triggers)
            self.ResponseTriggers.extend(response_triggers)
            self.RequestTriggerDescs.extend(request_trigger_descs)
            self.ResponseTriggerDescs.extend(response_trigger_descs)
            self.TriggerRequests.extend(requests)
            self.TriggerResponses.extend(responses)
            self.TriggerCount = self.TriggerCount + len(request_triggers)
            self.SetConfidence(2)
            return
          else:
            self.scnr.Trace("<i<br>>The pattern in the response times is inconsistent and therefore does not indicate SSRF")
            return
      elif not (relaxed_group_matched or strict_group_matched):
        self.scnr.Trace("<i<br>>The responses did not fall in any patterns that indicate SSRF")
        break

  def SetConfidence(self, conf):
    if conf > self.confidence:
      self.confidence = conf

  def AnalyzeTestResult(self):
    if len(self.RequestTriggers) > 0:
      self.ReportSSRF()

  def ReportSSRF(self):
    self.scnr.SetTraceTitle("Server Side Request Forgery Found", 10)
    pr = Finding(self.scnr.InjectedRequest.BaseUrl)
    pr.Title = "Server Side Request Forgery Found"
    pr.Summary = "Server Side Request Forgery been detected in the '{0}' parameter of the {1} section of the request.<i<br>><i<br>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.GetSummary())
    for reason in self.reasons:
      pr.AddReason(reason)

    for i in range(len(self.RequestTriggers)):
      pr.Triggers.Add(self.RequestTriggers[i], self.RequestTriggerDescs[i], self.TriggerRequests[i], self.ResponseTriggers[i], self.ResponseTriggerDescs[i], self.TriggerResponses[i])
    pr.Type = FindingType.Vulnerability
    pr.Severity = FindingSeverity.High
    if self.confidence == 3:
      pr.Confidence = FindingConfidence.High
    elif self.confidence == 2:
      pr.Confidence = FindingConfidence.Medium
    else:
      pr.Confidence = FindingConfidence.Low
    self.scnr.AddFinding(pr)

  def GetSummary(self):
    Summary = "Server Side Request Forgery is an issue where it is possible to forge an HTTP request on the server-side by sending the url in a request. For more details on this issue refer <i<cb>>http://cwe.mitre.org/data/definitions/918.html<i</cb>><i<br>><i<br>>"
    return Summary
  

  def GetDiffReason(self, payloads, time, time_delays, trigger_start, trigger_count):
    Reason = "IronWASP sent four payloads to the application.<i<br>>"
    ids = ["A", "B", "C", "D"]

    for i in range(len(ids)):
      payloads[i] = Tools.EncodeForTrace(payloads[i])
      Reason = Reason +"Payload {0} - <i<hlg>>{1}<i</hlg>><i<br>>".format(ids[i], payloads[i])
    
    Reason = Reason + "<i<br>>Payloads A and C are similar in nature. They both refer to ports 65555 and 66666 on the server which are invalid ports."
    Reason = Reason + "<i<br>>Payloads B and D are similar to each other but different from A & C. They both refer to ports 1 and 2 on the server which are valid ports."
    Reason = Reason + "<i<br>>If the application is vulnerable to SSRF then it will try to connect to these ports and connections to invalid potrs with throw an exception of different type than the exception or error caused by connecting to the valid ports 1 and 2 which are most likely to be closed."
    
    Reason = Reason + "<i<br>>This would mean that the response for Payloads A & C must be similar to each other and different from responses for Payloads B&D. "
    if time:
      Reason = Reason + "<i<br>><i<br>>The responses for the injected payloads were analyzed and it was found that the response times for Payloads A & C were similar to each other and were also different from response times for Payloads B & D, thereby indicating the presence of this vulnerability."
      Reason = Reason + "<i<br>>The responses times for the four payloads were:"
      Reason = Reason + "<i<br>>Payload A - {0}ms".format(time_delays[0])
      Reason = Reason + "<i<br>>Payload B - {0}ms".format(time_delays[1])
      Reason = Reason + "<i<br>>Payload C - {0}ms".format(time_delays[2])
      Reason = Reason + "<i<br>>Payload D - {0}ms".format(time_delays[3])
    else:
      Reason = Reason + "<i<br>><i<br>>The responses for the injected payloads were analyzed and it was found that Payloads A & C got a similar looking response and were also different from responses got from Payloads B & D, thereby indicating the presence of this vulnerability."
    
    #Trigger
    trigger_ids = []
    for i in range(trigger_start + 1, trigger_start + trigger_count + 1):
      trigger_ids.append(i)
    
    if time:
      ReasonType = "Delay"
    else:
      ReasonType = "Diff"
    
    #False Positive Check
    FalsePositiveCheck = "To check if this was a valid case or a false positive you can first manually look at the responses received for Payloads A, B, C and D. Analyze these payloads and verify if indeed A & C got similar responses and were different from B & D. "
    FalsePositiveCheck = FalsePositiveCheck + "You can also change the payloads for A & C by chaning the port number to some other invalid port and change payloads B & D to some other valid port numbers and check of the four response show the same pattern as before."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, trigger_ids, FalsePositiveCheck)
    return FR

p = ServerSideRequestForgery()
ActivePlugin.Add(p.GetInstance())


