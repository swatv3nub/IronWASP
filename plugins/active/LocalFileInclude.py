#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license
from IronWASP import *
from System import *
import clr
import re

#Inherit from the base ActivePlugin class
class LocalFileInclude(ActivePlugin):

  null_terminator = ["\000",""]
  files = {"etc/passwd" : "nix", "boot.ini" : "win", "Windows\\Win.ini" : "win"}
  file_ext = ["txt", "html", "jpg",""]
  drives = ["c:\\", "d:\\"]
  
  def GetInstance(self):
    p = LocalFileInclude()
    p.Name = "Local File Include"
    p.Description = "Active Plugin to check for Local File Include/Directory Traversal vulnerabilities"
    p.Version = "0.5"
    return p
  
  #Override the Check method of the base class with custom functionlity
  def Check(self, scnr):
    self.scnr = scnr
    self.confidence = 0
    self.RequestTriggers = []
    self.ResponseTriggers = []
    self.RequestTriggerDescs = []
    self.ResponseTriggerDescs = []
    self.TriggerRequests = []
    self.TriggerResponses = []
    self.reasons = []
    self.TriggerCount = 0
    self.slash_prefix = ""
    self.CheckForLocalFileInclude()
  
  def CheckForLocalFileInclude(self):
    self.scnr.Trace("<i<br>><i<h>>Checking for Local File Include:<i</h>>")
    self.slash_prefix = self.GetPrefix()
    self.CheckForLocalFileIncludeWithKnownFiles()
    self.CheckForLocalFileIncludeWithDownwardTraversal()
    self.AnalyzeTestResult()
    
  def GetPrefix(self):
    #Prefix detection logic is inspired by the WAVSEP LFI test cases
    self.scnr.Trace("<i<br>><i<b>>Identifying the prefix to use in payloads:<i</b>>")
    self.scnr.RequestTrace("  Injected paylaod - aaa")
    prefix_base_res = self.scnr.Inject("aaa")
    self.scnr.ResponseTrace("    ==> This response will be used as baseline for prefix detection")
    
    prefix = ""
    
    payloads = ["/", "\\", "file:/aaa"]
    messages = ["is a directory", "is a directory", "no such file or directory"]
    
    for i in range(len(payloads)):
      payload = payloads[i]
      message = messages[i]
      self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
      res = self.scnr.Inject(payload)
      if res.BodyString.lower().count(message) > prefix_base_res.BodyString.lower().count(message):
        prefix = payload
        self.scnr.ResponseTrace("    ==> <i<cb>>The message '{0}' occured {1} times in this response and {2} time in the baseline response. This indicates that the prefix should be {3}<i</cb>>".format(message, res.BodyString.lower().count(message), prefix_base_res.BodyString.lower().count(message), payload))
        return prefix
      else:
        self.scnr.ResponseTrace("    ==> Response does not indicate that {0} could be the prefix".format(payload))
    
    if self.scnr.PreInjectionParameterValue.startswith("/"):
      prefix = "/"
    elif self.scnr.PreInjectionParameterValue.startswith("\\"):
      prefix = "\\"
    elif self.scnr.PreInjectionParameterValue.startswith("file:"):
      prefix = "file:"
    return prefix
    
  def CheckForLocalFileIncludeWithKnownFiles(self):
    file_exts = []
    self.base_res = self.scnr.BaseResponse
    parts = self.scnr.PreInjectionParameterValue.split(".")
    if len(parts) > 1:
      file_exts.append(parts[len(parts) - 1])
    file_exts.extend(self.file_ext)
    
    self.scnr.Trace("<i<br>><i<h>>Checking for Local File Include with Known Files:<i</h>>")

    for f in self.files.keys():
      for nt in self.null_terminator:
        for fe in file_exts:
          if len(nt) == 0 and len(fe) > 0:
            continue#no point in adding a file extension without a null terminator
          payload = ""
          if self.slash_prefix == "file:":
            if self.files[f] == "nix":
              payload = "/{0}".format(f, nt)
            else:
              payload = "c:\\{0}".format(f, nt)
          else:
            if self.files[f] == "nix":
              payload = "{0}{1}{2}{3}".format(self.slash_prefix, "../" * 15, f, nt)
            else:
              payload = "{0}{1}{2}{3}".format(self.slash_prefix, "..\\" * 15, f, nt)
          
          if len(fe) > 0:
            payload = "{0}.{1}".format(payload, fe)
          self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
          res = self.scnr.Inject(payload)
          downloaded_file_info = self.GetDownloadedFileInfo(res, f)
          if len(downloaded_file_info) > 0:
            self.scnr.ResponseTrace("    ==> <i<cr>>Response contains contens of {0}<i</cr>>".format(f))
            if self.slash_prefix == "file:":
              self.AddToTriggers(payload, "The payload in this request refers to the {0} file by using the file: protocol. The payload is {1}".format(f, payload), downloaded_file_info, "This response contains contents of the {0} file. This was caused by the payload".format(f))
            else:
              self.AddToTriggers(payload, "The payload in this request refers to the {0} file by traversing upwards in the directory structure. The payload is {1}".format(f, payload), downloaded_file_info, "This response contains contents of the {0} file. This was caused by the payload".format(f))
            self.SetConfidence(3)
            slash = ""
            if self.files[f] == "nix":
              slash = "/"
            else:
              slash = "\\"
            reason = self.GetEchoReason(payload, f, downloaded_file_info, slash, self.TriggerCount, self.slash_prefix)
            self.reasons.append(reason)
          else:
            self.scnr.ResponseTrace("    ==> No trace of {0}".format(f))
    
  def CheckForLocalFileIncludeWithDownwardTraversal(self):
    slashes = ["/", "\\"]
    for slash in slashes:
      self.CheckForLocalFileIncludeWithDownwardTraversalWithSlash(slash)
    
  def CheckForLocalFileIncludeWithDownwardTraversalWithSlash(self, slash):
    #check downward traversal
    #indicates presence of file read function and also a insecure direct object reference in that function
    self.scnr.Trace("<i<br>><i<b>>Checking for Downward Directory Traversal:<i</b>>")
    self.scnr.Trace("<i<br>>Normal Response Code - {0}. Length -{0}".format(self.base_res.Code, self.base_res.BodyLength))
    
    payload_a = "aa<s>..<s>{0}".format(self.scnr.PreInjectionParameterValue)
    payload_a = payload_a.replace("<s>", slash)
    self.scnr.RequestTrace("  Injected payload - {0}".format(payload_a))
    res_a = self.scnr.Inject(payload_a)
    req_a = self.scnr.InjectedRequest
    self.scnr.ResponseTrace("    ==> Got Response. Code- {0}. Length- {1}".format(res_a.Code, res_a.BodyLength))
    
    payload_a1 = "aa..<s>{0}".format(self.scnr.PreInjectionParameterValue)
    payload_a1 = payload_a1.replace("<s>", slash)
    self.scnr.RequestTrace("  Injected payload - {0}".format(payload_a1))
    res_a1 = self.scnr.Inject(payload_a1)
    req_a1 = self.scnr.InjectedRequest
    self.scnr.ResponseTrace("    ==> Got Response. Code- {0}. Length- {1}".format(res_a1.Code, res_a1.BodyLength))
    
    payload_b = "bb<s>..<s>{0}".format(self.scnr.PreInjectionParameterValue)
    payload_b = payload_b.replace("<s>", slash)
    self.scnr.RequestTrace("  Injected payload - {0}".format(payload_b))
    res_b = self.scnr.Inject(payload_b)
    req_b = self.scnr.InjectedRequest
    self.scnr.ResponseTrace("    ==> Got Response. Code- {0}. Length- {1}".format(res_b.Code, res_b.BodyLength))
    
    payload_b1 = "bb..<s>{0}".format(self.scnr.PreInjectionParameterValue)
    payload_b1 = payload_b1.replace("<s>", slash)
    self.scnr.RequestTrace("  Injected payload - {0}".format(payload_b1))
    res_b1 = self.scnr.Inject(payload_b1)
    req_b1 = self.scnr.InjectedRequest
    self.scnr.ResponseTrace("    ==> Got Response. Code- {0}. Length- {1}".format(res_b1.Code, res_b1.BodyLength))
    
    self.scnr.Trace("<i<br>>Analysing the responses for patterns...")
    
    #Analyzing the responses for patterns
    sc = SimilarityChecker()
    sc.Add("a", res_a)
    sc.Add("a1", res_a1)
    sc.Add("b", res_b)
    sc.Add("b1", res_b1)
    sc.Check()
    
    requests = [req_a, req_a1, req_b, req_b1]
    responses = [res_a, res_a1, res_b, res_b1]
    request_trigger_descs = []
    request_trigger_descs.append("This payload refers to the {0} file by doing a proper upward directory traversal of a dummy directory 'aa'. The payload is {1}".format(self.scnr.PreInjectionParameterValue, payload_a))
    request_trigger_descs.append("This payload does not do a proper upward directory traversal of the dummy directory 'aa' and so does not refer to the {0} file. The payload is {1}".format(self.scnr.PreInjectionParameterValue, payload_a1))
    request_trigger_descs.append("This payload refers to the {0} file by doing a proper upward directory traversal of a dummy directory 'bb'. The payload is {1}".format(self.scnr.PreInjectionParameterValue, payload_b))
    request_trigger_descs.append("This payload does not do a proper upward directory traversal of the dummy directory 'bb' and so does not refer to the {0} file. The payload is {1}".format(self.scnr.PreInjectionParameterValue, payload_b1))
    response_trigger_descs = []
    response_trigger_descs.append("The contents of this response are different from the response of the next trigger but are similar to the response of the trigger after the next.")
    response_trigger_descs.append("The contents of this response are different from the response of the previous trigger but are similar to the response of the trigger after the next.")
    response_trigger_descs.append("The contents of this response are different from the response of the next trigger but are similar to the response of the trigger before the previous.")
    response_trigger_descs.append("The contents of this response are different from the response of the previous trigger but are similar to the response of the trigger before the previous.")
    request_triggers = [payload_a, payload_a1, payload_b, payload_b1]
    response_triggers = ["","","",""]
    
    for group in sc.StrictGroups:
      if group.Count == 2:
        if group.HasKey("a") and group.HasKey("b"):
          self.scnr.Trace("<i<br>><i<cr>>Responses for traversal based payloads are similar to each other and are different from non-traversal based responses. Indicates presence of LFI.<i</cr>>")
          
          reason = self.GetDiffReason([payload_a, payload_a1, payload_b, payload_b1], self.scnr.PreInjectionParameterValue, slash, self.TriggerCount, len(request_triggers))
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
    
    for group in sc.RelaxedGroups:
      if group.Count == 2:
        if group.HasKey("a") and group.HasKey("b"):
          self.scnr.Trace("<i<br>><i<cr>>Responses for traversal based payloads are similar to each other and are different from non-traversal based responses. Indicates presence of LFI.<i</cr>>")
          
          reason = self.GetDiffReason([payload_a, payload_a1, payload_b, payload_b1], self.scnr.PreInjectionParameterValue, slash, self.TriggerCount, len(request_triggers))
          self.reasons.append(reason)
          
          self.RequestTriggers.extend(request_triggers)
          self.ResponseTriggers.extend(response_triggers)
          self.RequestTriggerDescs.extend(request_trigger_descs)
          self.ResponseTriggerDescs.extend(response_trigger_descs)
          self.TriggerRequests.extend(requests)
          self.TriggerResponses.extend(responses)
          self.TriggerCount = self.TriggerCount + len(request_triggers)
          self.SetConfidence(1)
          return
    
    self.scnr.Trace("<i<br>>The responses did not fall in any patterns that indicate LFI")


  def GetDownloadedFileInfo(self, res, file):
    bs = res.BodyString.lower()
    bbs = self.base_res.BodyString.lower()
    
    if file == "etc/passwd":	
      bs_c = bs.count("root:x:0:0:")
      bbs_c = bbs.count("root:x:0:0:")
      if bs_c > bbs_c:
        return "root:x:0:0:"
      elif bs_c == bbs_c and self.scnr.PreInjectionParameterValue.count("etc/passwd") > 0:
        return "root:x:0:0:"
      
      bs_c = bs.count("root:!:x:0:0:")
      bbs_c = bbs.count("root:!:x:0:0:")
      if bs_c > bbs_c:
        return "root:!:x:0:0:"
      elif bs_c == bbs_c and self.scnr.PreInjectionParameterValue.count("passwd") > 0:
        return "root:!:x:0:0:"
      
    elif file == "boot.ini":
      bs_c_1 = bs.count("[boot loader]")
      bbs_c_1 = bbs.count("[boot loader]")
      bs_c_2 = bs.count("multi(")
      bbs_c_2 = bbs.count("multi(")
      if bs_c_1 > bbs_c_1 and bs_c_2 > bbs_c_2:
        return "[boot loader]"
      elif bs_c_1 == bbs_c_1 and bs_c_2 == bbs_c_2 and self.scnr.PreInjectionParameterValue.count("boot.ini") > 0:
        return "[boot loader]"
    
    elif file == "Windows\\Win.ini":
      bs_c = bs.count("for 16-bit app support")
      bbs_c = bbs.count("for 16-bit app support")
      if bs_c > bbs_c:
        return "for 16-bit app support"
      elif bs_c == bbs_c and self.scnr.PreInjectionParameterValue.count("Win.ini") > 0:
        return "for 16-bit app support"
    return ""
  
  def SetConfidence(self, conf):
    if conf > self.confidence:
      self.confidence = conf
  
  def AnalyzeTestResult(self):
    if len(self.RequestTriggers) > 0:
      self.ReportLocalFileInclude()
  
  def AddToTriggers(self, RequestTrigger, RequestTriggerDesc, ResponseTrigger, ResponseTriggerDesc):
    self.RequestTriggers.append(RequestTrigger)
    self.ResponseTriggers.append(ResponseTrigger)
    self.RequestTriggerDescs.append(RequestTriggerDesc)
    self.ResponseTriggerDescs.append(ResponseTriggerDesc)
    self.TriggerRequests.append(self.scnr.InjectedRequest.GetClone())
    self.TriggerResponses.append(self.scnr.InjectionResponse.GetClone())
    self.TriggerCount = self.TriggerCount + 1
  
  def ReportLocalFileInclude(self):
    self.scnr.SetTraceTitle("Local File Include Found", 10)
    pr = Finding(self.scnr.InjectedRequest.BaseUrl)
    pr.Title = "Local File Include Found"
    pr.Summary = "Local File Include/Path Traversal been detected in the '{0}' parameter of the {1} section of the request.<i<br>><i<br>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.GetSummary())
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
    Summary = "Local File Include is an issue where it is possible to load and view the raw contents of any files present on the web server. For more details on this issue refer <i<cb>>https://www.owasp.org/index.php/Path_Traversal<i</cb>><i<br>><i<br>>"
    return Summary
  
  def GetEchoReason(self, payload, file_name, file_contents, slash, Trigger, Prefix):
    payload  = Tools.EncodeForTrace(payload)
    #Reason = "IronWASP sent <i>../../../../../../../../../../../../../etc/passwd\000.txt</i> as payload to the application. "
    Reason = "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application. ".format(payload)
    #Reason = Reason + "This payload tries to refer to the file <i>/etc/passwd</i> by traversing from the current directory with a series of <i>../</i>. "
    if Prefix == "file:":
      Reason = Reason + "This payload tries to refer to the file <i<hlg>>{0}<i</hlg>> by using the <i<hlg>>file:<i</hlg>> protocol.".format(file_name)
    else:
      Reason = Reason + "This payload tries to refer to the file <i<hlg>>{0}<i</hlg>> by traversing from the current directory with a series of <i<hlg>>..{1}<i</hlg>>. ".format(file_name, slash)
    #Reason = Reason + "If the application is vulnerable it will load the <i>/etc/passwd</i> file and send its contents in the response. "
    Reason = Reason + "If the application is vulnerable it will load the <i<hlg>>{0}<i</hlg>> file and send its contents in the response. ".format(file_name)
    #Reason = Reason + "The response that came back from the application after the payload was injected had the text <i>root:x:0:0:</i>, which is usually found in <i>/etc/passwd</i> files. This indicates that the <i>/etc/passwd</i> file was loaded and its content printed in the response.".format(payload, code)
    Reason = Reason + "The response that came back from the application after the payload was injected had the text <i<hlg>>{0}<i</hlg>>, which is usually found in <i<hlg>>{1}<i</hlg>> files. This indicates that the <i<hlg>>{1}<i</hlg>> file was loaded and its content printed in the response.".format(file_contents, file_name)
    
    ReasonType = "Echo"
    
    #False Positive Check
    #Reason = Reason + "To check if this was a valid case or a false positive you can first manually look at the response sent for this payload and determine if it actually contains the contents of the <i<hlg>>/etc/passwd<i</hlg>> file. "
    FalsePositiveCheck = "To check if this was a valid case or a false positive you can first manually look at the response sent for this payload and determine if it actually contains the contents of the <i<hlg>>{0}<i</hlg>> file. ".format(file_name)
    FalsePositiveCheck = FalsePositiveCheck + "After that you can try changing the file name to something else and see if the server prints those file contents."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, Trigger, FalsePositiveCheck)
    return FR


  def GetDiffReason(self, payloads, file_name, slash, trigger_start, trigger_count):
    Reason = "IronWASP sent four payloads to the application.<i<br>>"
    ids = ["A", "B", "C", "D"]
    #Payload A - <i>aa/../abcd.jpg</i>
    #Payload B - <i>aa../abcd.jpg</i>
    #Payload C - <i>bb/../abcd.jpg</i>
    #Payload D - <i>bb../abcd.jpg</i>

    for i in range(len(ids)):
      payloads[i] = Tools.EncodeForTrace(payloads[i])
      Reason = Reason +"Payload {0} - <i<hlg>>{1}<i</hlg>><i<br>>".format(ids[i], payloads[i])
    
    Reason = Reason + "<i<br>>Payloads A and C are similar in nature. They both refer to the file <i<hlg>>{0}<i</hlg>> ".format(file_name)
    Reason = Reason + "by including an imaginary directory in the path (aa & bb) but then also invalidating it by traversing upwards by one directory using <i<hlg>>..{0}<i</hlg>>. ".format(slash)
    #Reason = Reason + "So these payloads must have the same effect as refering to the file <i<hlg>>abcd.jpg<i</hlg>> normally."
    Reason = Reason + "So these payloads must have the same effect as referring to the file <i<hlg>>{0}<i</hlg>> normally.".format(file_name)
    
    #Reason = Reason + "<i<br>>Payloads B and D are similar to each other but different from A & C. They refer to the file <i>abcd.jpg</i> inside invalid directories (aa & bb)."
    Reason = Reason + "<i<br>>Payloads B and D are similar to each other but different from A & C. They refer to the file <i<hlg>>{0}<i</hlg>> inside invalid directories (aa & bb).".format(file_name)
    
    Reason = Reason + "<i<br>>If the application is vulnerable to Local File Include then the response for Payloads A & C must be similar to each other and different from responses for Payloads B&D. "
    Reason = Reason + "The responses for the injected payloads were analyzed and it was found that Payloads A & C got a similar looking response and were also different from responses got from Payloads B & D, thereby indicating the presence of this vulnerability."
    
    #Trigger
    trigger_ids = []
    for i in range(trigger_start + 1, trigger_start + trigger_count + 1):
      trigger_ids.append(i)
    
    ReasonType = "Diff"
    
    #False Positive Check
    FalsePositiveCheck = "To check if this was a valid case or a false positive you can first manually look at the responses received for Payloads A, B, C and D. Analyze these payloads and verify if indeed A & C got similar responses and were different from B & D. "
    FalsePositiveCheck = FalsePositiveCheck + "You can also change the payloads for A & C by adding one more invalid directory and one more <i<hlg>>..{0}<i</hlg>> to invalidate that directory. ".format(slash)
    FalsePositiveCheck = FalsePositiveCheck + "This must get the same response as the responses for A & C."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, trigger_ids, FalsePositiveCheck)
    return FR

p = LocalFileInclude()
ActivePlugin.Add(p.GetInstance())
