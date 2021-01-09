#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license
from IronWASP import *
from System import *
import clr
import re

#Inherit from the base ActivePlugin class
class SQLInjection(ActivePlugin):
  
  error_regex_raw = []
  error_regex = []
  time_check = []
  
  def GetInstance(self):
    p = SQLInjection()
    p.Name = "SQL Injection"
    p.Description = "Plugin to discover SQL Injection vulnerabilities"
    p.Version = "0.6"
    return p
  
  #Override the Check method of the base class with custom functionlity
  def Check(self, Scnr):
    
    self.Scnr = Scnr
    self.RequestTriggers = []
    self.ResponseTriggers = []
    self.RequestTriggerDescs = []
    self.ResponseTriggerDescs = []
    self.TriggerRequests = []
    self.TriggerResponses = []
    self.TriggerCount = 0
    self.reasons = []
    self.Confidence = 0
    self.base_response = self.Scnr.BaseResponse
    
    self.ErrorCount = [0,0,0]
    self.Errors = []
    self.ErrorTriggerCount = 0
    
    self.Scnr.Trace("<i<br>><i<h>>Checking for SQL Injection:<i</h>>")
    overall_error_score = self.CheckForErrorBasedSQLi()
    overall_blind_score = self.CheckForBlindSQLi()
    
    overall_score = overall_error_score + overall_blind_score
    
    if len(self.RequestTriggers) == self.ErrorTriggerCount and  (self.ErrorCount[0] + self.ErrorCount[1] + self.ErrorCount[2]) > 0 and (self.ErrorCount[0] == self.ErrorCount[1] == self.ErrorCount[2]):
      self.ReportSQLError(self.Errors)
    elif overall_score > 7:
      self.ReportSQLInjection(FindingConfidence.High)
    elif overall_score > 4:
      self.ReportSQLInjection(FindingConfidence.Medium)
    elif overall_score > 3:
      self.ReportSQLInjection(FindingConfidence.Low)
    #overall_blind_score = self.CheckForBlindSQLi(Request, Scanner)
    #overall_score = overall_error_score + overall_blind_score
    #if(overall_score == 0):
    #	return
  def CheckForErrorBasedSQLi(self):
    self.Scnr.Trace("<i<br>><i<h>>Checking for Error based Injection:<i</h>>")
    self.Scnr.Trace("<i<br>>Sending a request with a normal value to get a Error baseline")
    self.Scnr.RequestTrace("  Injected 123 - ")
    err_base_res = self.Scnr.Inject("123")
    self.Scnr.ResponseTrace("  ==> Code {0} | Length {0}".format(err_base_res.Code, err_base_res.BodyLength))
    
    payloads = ["'", "\"", "\xBF'\"(", "(", ")"]
    final_error_score = 0
    for payload in payloads:
      self.Scnr.RequestTrace("  Injected {0} - ".format(payload))
      if payload == "\xBF'\"(":
        inj_res = self.Scnr.RawInject(payload)
      else:
        inj_res = self.Scnr.Inject(payload)
      score = self.AnalyseInjectionResultForError(payload, inj_res, err_base_res)
      if score > final_error_score:
        final_error_score = score
    self.ErrorTriggerCount = len(self.RequestTriggers)
    return final_error_score
  
  def AnalyseInjectionResultForError(self, payload, payload_response, err_base_res):
    res = payload_response

    triggers = []
    all_error_matches = {}
    
    error_score = 0
    for i in range(len(self.error_regex)):
      error_re = self.error_regex[i]
      error_re_raw = self.error_regex_raw[i]
      matches = error_re.findall(res.BodyString)
      if len(matches) > 0:
        original_error_matches = error_re.findall(self.base_response.BodyString)
        base_error_matches = error_re.findall(err_base_res.BodyString)
        all_error_matches[error_re_raw] = [len(matches),len(original_error_matches), len(base_error_matches)]
        triggers.extend(matches)
        
        self.ErrorCount[0] = self.ErrorCount[0] + len(matches)
        self.ErrorCount[1] = self.ErrorCount[1] + len(original_error_matches)
        self.ErrorCount[2] = self.ErrorCount[2] + len(base_error_matches)
    
    if len(all_error_matches) > 0:
      self.Errors.extend(triggers)
      for error_key,(inj_matches,base_matches,base_err_matches) in all_error_matches.items():
        self.Scnr.ResponseTrace("      <i<cr>>Got {0} occurance[s] of error signature. Normal Response had {1} occurance[s]<i</cr>>. Error Baseline Response had {2} occurance[s]<i</cr>>.<i<b>>Error Signature:<i</b>> {3}".format(inj_matches, base_matches, base_err_matches, error_key))
        if self.ErrorCount[0] == self.ErrorCount[1] == self.ErrorCount[2]:
          error_score = 4
        else:
          error_score = 7
    else:
      self.Scnr.ResponseTrace("      No errors")
    
    if error_score > 0:
      self.RequestTriggers.append(payload)
      self.RequestTriggerDescs.append("The payload in this request is meant to trigger database error messages. The payload is {0}.".format(payload))
      self.ResponseTriggers.append("\r\n".join(triggers))
      self.ResponseTriggerDescs.append("This response contains database error messages.")
      self.TriggerRequests.append(self.Scnr.InjectedRequest.GetClone())
      self.TriggerResponses.append(res)
      self.TriggerCount = self.TriggerCount + 1
      
      reason = self.GetErrorReason(payload, triggers, self.TriggerCount)
      self.reasons.append(reason)
      
    return error_score
  
  def CheckForBlindSQLi(self):
    self.Scnr.Trace("<i<br>><i<h>>Checking for Blind Injection:<i</h>>")
    is_int = False
    int_value = 0
    str_value = ""
    str_value = self.Scnr.PreInjectionParameterValue.replace("'","").replace('"',"")
    try:
      int_value = int(self.Scnr.PreInjectionParameterValue)
      is_int = True
    except:
      pass
    blind_int_math_score = 0
    blind_str_conc_score = 0
    blind_bool_score = 0
    blind_time_score = 0
    
    if is_int:
      blind_int_math_score = self.InjectBlindIntMath(int_value)
    else:
      blind_int_math_score = self.InjectBlindIntMath(0)
      
    if len(str_value) > 1:
      blind_str_conc_score = self.InjectBlindStrConc(str_value)
    
    blind_bool_score = self.InjectBlindBool()
    
    blind_time_score = self.CheckBlindTime()
    
    if blind_int_math_score  + blind_str_conc_score + blind_bool_score + blind_time_score > 0:
      return 6
    else:
      return 0
    
  def InjectBlindIntMath(self, int_value):
    self.Scnr.Trace("<i<br>><i<h>>Checking for Blind Injection with Integer Math:<i</h>>")
    
    val = int_value
    
    #Addition Algo
    #if val < 2 then val = 3
    #(val - 1) + 1
    #(val - 2) + 2
    #
    #(val) + 5
    #(val - 1) + 6
    #
    #(val) + "a"
    #(val) + "b"
    #
    if val < 2:
      val = 3#adjust the value to be suitable for addition based check
    plus_left = [ val-1, val-2, val, val-1, val, val]
    plus_right = [ 1, 2, 5, 6, "a", "b"]
    
    #Subtraction Algo
    #(val + 1) - 1
    #(val + 2) - 2
    #
    #if val < 6 then val = 11
    #
    #(val) - 5
    #(val + 1) - 6
    #
    #(val) - "a"
    #(val) - "b"
    #
    val = int_value
    if val < 6:
      sub_val = 11#adjust the value to be suitable for subtraction based check
    else:
      sub_val = val
    minus_left = [ val+1, val+2, sub_val, sub_val+1, val, val]
    minus_right = [ 1, 2, 5, 6, "a", "b"]
    symbols = [ "+", "-"]
    keys = [ "a", "aa", "b", "bb", "c", "cc"]
    
    for ii in range(2):
      sym = symbols[ii]
      left = []
      right = []
      if sym == "+":
        self.Scnr.Trace("<i<br>>  <i<b>>Checking Addition:<i</b>>")
        left.extend(plus_left)
        right.extend(plus_right)
      else:
        self.Scnr.Trace("<i<br>>  <i<b>>Checking Subtraction:<i</b>>")
        left.extend(minus_left)
        right.extend(minus_right)
      
      #variables to keep track for rechecking
      first_strict_signature = ""
      first_relaxed_signature = ""
      second_strict_signature = ""
      second_relaxed_signature = ""
      confidence = 0
      vuln = False
      first_strict_vuln = False
      first_relaxed_vuln = False
      
      for j in range(2):
        if j == 1 and not (first_strict_vuln or first_relaxed_vuln):
          break
        payloads = []
        requests = []
        responses = []
        sc = SimilarityChecker()
        self.Scnr.Trace("<i<br>>")
        for i in range(6):
          payload = "{0}{1}{2}".format(left[i], sym, right[i])
          self.Scnr.RequestTrace("  Request Key: '{0}' - Injecting {1} ".format(keys[i], payload))
          res = self.Scnr.Inject(payload)
          #store the request and responses to be added to the vulnerability data if SQLi is found
          payloads.append(payload)
          requests.append(self.Scnr.InjectedRequest.GetClone())
          responses.append(res)
          sc.Add(keys[i], res)
          self.Scnr.ResponseTrace(" ==> Code-{0} Length-{1}".format(res.Code, res.BodyLength))
        sc.Check()
        
        self.Scnr.Trace("<i<br>>  The responses are analyzed for similarity based grouping to determine if injection succeeded.")
        self.Scnr.Trace("  Analysis Results:")
        self.Scnr.Trace("  Strict Groups Signature: {0}".format(sc.StrictGroupsSignature))
        self.Scnr.Trace("  Relaxed Groups Signature: {0}".format(sc.RelaxedGroupsSignature))
        
        if j == 0:
          first_strict_signature = sc.StrictGroupsSignature
          first_relaxed_signature = sc.RelaxedGroupsSignature
          
          if self.IsBlindMathInjectableGroupingCheck(sc.StrictGroups):
            self.Scnr.Trace("  <i<b>>Strict Grouping indicates that injection succeeded. Rechecking to confirm.<i</b>>")
            if j == 0:
              first_strict_vuln = True
          else:
            self.Scnr.Trace("  Strict Grouping does not indicates that injection succeeded.")
          
          if self.IsBlindMathInjectableGroupingCheck(sc.RelaxedGroups):
            self.Scnr.Trace("  <i<b>>Relaxed Grouping indicates that injection succeeded. Rechecking to confirm.<i</b>>")
            if j == 0:
              first_relaxed_vuln = True
          else:
            self.Scnr.Trace("  Relaxed Grouping does not indicates that injection succeeded.")
        else:
          second_strict_signature = sc.StrictGroupsSignature
          second_relaxed_signature = sc.RelaxedGroupsSignature
          vuln = False
          
          if first_strict_vuln and first_strict_signature == second_strict_signature:
            vuln = True
            confidence = confidence + 1
            self.Scnr.Trace("  <i<cr>>Even the second time Strict Grouping indicates that injection succeeded.<i</cr>>")
          else:
            self.Scnr.Trace("  Strict Grouping does not indicate that injection succeeded.")
          
          if first_relaxed_vuln and first_relaxed_signature == second_relaxed_signature:
            vuln = True
            confidence = confidence + 1
            self.Scnr.Trace("  <i<cr>>Even the second time Relaxed Grouping indicates that injection succeeded.<i</cr>>")
          else:
            self.Scnr.Trace("  Relaxed Grouping does not indicate that injection succeeded.")
          
          if vuln:
            self.RequestTriggers.extend(payloads)
            self.TriggerRequests.extend(requests)
            self.TriggerResponses.extend(responses)
            
            for i in range(len(payloads)):
              self.ResponseTriggers.append("")
              self.ResponseTriggerDescs.append("Refer to the 'Reasons' section of this vulnerabilty's description to understand how to interpret this response.")
              if i < 4:
                if sym == "+":
                  self.RequestTriggerDescs.append("The payload in this request tries to add the numbers {0} and {1}.".format(plus_left[i], plus_right[i]))
                else:
                  self.RequestTriggerDescs.append("The payload in this request tries to subtract the number {0} from {1}.".format(minus_left[i], minus_right[i]))
              else:
                if sym == "+":
                  self.RequestTriggerDescs.append("The payload in this request is an invalid attempt to add the number {0} with string {1}.".format(plus_left[i], plus_right[i]))
                else:
                  self.RequestTriggerDescs.append("The payload in this request is an invalid attempt to subtract the number {0} from the string {1}.".format(minus_left[i], minus_right[i]))
            
            self.TriggerCount = self.TriggerCount + 6
            
            self.second_group = []
            for item in ["A", "B", "C", "D", "E", "F"]:
              if self.first_group.count(item) == 0:
                self.second_group.append(item)
            
            if sym == "+":
              reason = self.GetBlindMathAddReason(payloads, plus_left[0] + plus_right[0], plus_left[2] + plus_right[2], self.first_group, self.second_group, self.TriggerCount)
            else:
              reason = self.GetBlindMathSubtractReason(payloads, minus_left[0] - minus_right[0], minus_left[2] - minus_right[2], self.first_group, self.second_group, self.TriggerCount)
            self.reasons.append(reason)
            
            return confidence
    return 0
  
  def IsBlindMathInjectableGroupingCheck(self, groups):
    self.first_group = []
    self.second_group = []
    
    vuln = False
    for group in groups:
      if group.Count == 2 or group.Count == 4:
        m = 0
        if group.HasKey("a") and group.HasKey("aa"):
          m = m + 1
          if len(self.first_group) == 0:
            self.first_group.append("A")
            self.first_group.append("B")
          else:
            self.second_group.append("A")
            self.second_group.append("B")
        if group.HasKey("b") and group.HasKey("bb"):
          m = m + 1
          if len(self.first_group) == 0:
            self.first_group.append("C")
            self.first_group.append("D")
          else:
            self.second_group.append("C")
            self.second_group.append("D")
        if group.HasKey("c") and group.HasKey("cc"):
          m = m + 1
          if len(self.first_group) == 0:
            self.first_group.append("E")
            self.first_group.append("F")
          else:
            self.second_group.append("E")
            self.second_group.append("F")
        if (group.Count == 2 and m == 1) or (group.Count == 4 and m == 2):
          #indicates SQL Injection report it
          vuln = True
      else:
        vuln = False
        break
    return vuln
  
  def InjectBlindStrConc(self, str_value):
    BlindConcInjectionScore = 0
    self.Scnr.Trace("<i<br>><i<h>>Checking for Blind Injection with String Concatenation:<i</h>>")
    blind_str_conc_res = []
    if len(str_value) < 2:
      str_value = "aaa"
    str_value_first_part = str_value[:1]
    str_value_second_part = str_value[1:]
    
    quotes = ["'", '"']
    joiners = [ '||', "+", " "]
    keys = [ "Oracle", "MS SQL", "MySQL"]
    requests = []
    responses = []
    
    for quote in quotes:
      if quote == "'":
        self.Scnr.Trace("<i<br>>  <i<b>>Checking with Single Quotes:<i</b>>")
      else:
        self.Scnr.Trace("<i<br>>  <i<b>>Checking with Double Quotes:<i</b>>")
      
      #variables to keep track of rechecking
      first_strict_signature = ""
      first_relaxed_signature = ""
      second_strict_signature = ""
      second_relaxed_signature = ""
      confidence = 0
      vuln = False
      first_strict_vuln = False
      first_relaxed_vuln = False
      
      for j in range(2):
        if j == 1 and not (first_strict_vuln or first_relaxed_vuln):
          break
        payloads = []
        requests = []
        responses = []
        sc = SimilarityChecker()
        self.Scnr.Trace("<i<br>>")
        for i in range(3):
          payload = "{0}{1}{2}{3}{4}".format(str_value_first_part, quote, joiners[i], quote, str_value_second_part)
          self.Scnr.RequestTrace("  Request Key: '{0}' - Injecting {1}".format(keys[i], payload))
          res = self.Scnr.Inject(payload)
          payloads.append(payload)
          requests.append(self.Scnr.InjectedRequest.GetClone())
          responses.append(res)
          sc.Add(keys[i], res)
          self.Scnr.ResponseTrace(" ==> Code-{0} Length-{1}".format(res.Code, res.BodyLength))
        
        sc.Check()
        
        self.Scnr.Trace("<i<br>>  The responses are analyzed for similarity based grouping to determine if injection succeeded.")
        self.Scnr.Trace("  Analysis Results:")
        self.Scnr.Trace("  Strict Groups Signature: {0}".format(sc.StrictGroupsSignature))
        self.Scnr.Trace("  Relaxed Groups Signature: {0}".format(sc.RelaxedGroupsSignature))
        if j == 0:
          first_strict_signature = sc.StrictGroupsSignature
          first_relaxed_signature = sc.RelaxedGroupsSignature
          
          if self.IsBlindStrConcInjectableGroupingCheck(sc.StrictGroups):
            self.Scnr.Trace("  <i<b>>Strict Grouping indicates that injection succeeded. Rechecking to confirm.<i</b>>")
            if j == 0:
              first_strict_vuln = True
          else:
            self.Scnr.Trace("  Strict Grouping does not indicates that injection succeeded.")
          
          if self.IsBlindStrConcInjectableGroupingCheck(sc.RelaxedGroups):
            self.Scnr.Trace("  <i<b>>Relaxed Grouping indicates that injection succeeded. Rechecking to confirm.<i</b>>")
            if j == 0:
              first_relaxed_vuln = True
          else:
            self.Scnr.Trace("  Relaxed Grouping does not indicates that injection succeeded.")
        else:
          second_strict_signature = sc.StrictGroupsSignature
          second_relaxed_signature = sc.RelaxedGroupsSignature
          vuln = False
          db = ""
          
          if first_strict_vuln and first_strict_signature == second_strict_signature:
            vuln = True
            confidence = confidence + 1
            self.Scnr.Trace("  <i<cr>>Even the second time Strict Grouping indicates that injection succeeded.<i</cr>>")
            for g in sc.StrictGroups:
              if g.Count == 1:
                db = g.GetKeys()[0]
          else:
            self.Scnr.Trace("  Strict Grouping does not indicate that injection succeeded.")
          
          if first_relaxed_vuln and first_relaxed_signature == second_relaxed_signature:
            vuln = True
            confidence = confidence + 1
            self.Scnr.Trace("  <i<cr>>Even the second time Relaxed Grouping indicates that injection succeeded.<i</cr>>")
            for g in sc.RelaxedGroups:
              if g.Count == 1:
                db = g.GetKeys()[0]
          else:
            self.Scnr.Trace("  Relaxed Grouping does not indicate that injection succeeded.")
          
          if vuln:
            self.RequestTriggers.extend(payloads)
            self.TriggerRequests.extend(requests)
            self.TriggerResponses.extend(responses)
            non_db = []
            non_db.extend(keys)
            non_db.remove(db)
            for i in range(len(payloads)):
              self.ResponseTriggers.append("")
              self.RequestTriggerDescs.append("The payload in this request tries to concatenate two strings as per {0} database's syntax. The payload is {1}".format(keys[i], payloads[i]))
              if keys[i] == db:
                self.ResponseTriggerDescs.append("This response is different from the responses recieved for the payloads that used {0} and {1} databases' concatenation syntax.".format(non_db[0], non_db[1]))
              else:
                non_db.remove(keys[i])
                self.ResponseTriggerDescs.append("This response is different from the response recieved for the payloads that used {0} database's concatenation syntax but similar to the response for the payload that used {1} database's concatenation syntax".format(db, non_db[0]))
                non_db.append(keys[i])
            
            self.TriggerCount = self.TriggerCount + 3
            
            reason = self.GetBlindConcatReason(payloads, db, self.TriggerCount)
            self.reasons.append(reason)
            
            return confidence
    return 0
  
  def IsBlindStrConcInjectableGroupingCheck(self, groups):
    vuln = False
    if len(groups) == 2:
      vuln = True
    return vuln
  
  def InjectBlindBool(self):
    score = 0
    
    self.Scnr.Trace("<i<br>><i<h>>Checking for Blind Injection with Boolean check:<i</h>>")
    
    prefix = self.Scnr.PreInjectionParameterValue
    
    int_trailers = [ "8=8--", "7=5--", "7=7--", "5=8--"]
    char_trailers = [ "<q>s<q>=<q>s", "<q>s<q>=<q>r", "<q>t<q>=<q>t", "<q>t<q>=<q>r"]
    keys = [ "true-a", "false-a", "true-b", "false-b"]
    quotes = [ "'", '"']
    
    self.Scnr.Trace("<i<br>>  <i<b>>Checking with OR Operator:<i</b>>")
    clean_prefix = prefix.replace("'","").replace('"',"")
    or_prefix = clean_prefix + "xxx"#this is to change the prefix to an invalid value to help with OR
    for quote in quotes:
      score = score + self.CheckForBlindBoolWith(or_prefix, quote, "or", int_trailers)
      score = score + self.CheckForBlindBoolWith(or_prefix, quote, "or", char_trailers)
    
    #do one check with a number as prefix without any quotes
    if clean_prefix == "21":
      or_prefix = "22"
    else:
      or_prefix = "21"
    score = score + self.CheckForBlindBoolWith(or_prefix, "", "or", int_trailers)
    
    self.Scnr.Trace("<i<br>>  <i<b>>Checking with AND Operator:<i</b>>")
    for quote in quotes:
      and_prefix = prefix.replace(quote, "")
      score = score + self.CheckForBlindBoolWith(and_prefix, quote, "and", int_trailers)
      score = score + self.CheckForBlindBoolWith(and_prefix, quote, "and", char_trailers)
    
    return score
  
  def CheckForBlindBoolWith(self, prefix, quote, operator, trailers):
    keys = [ "true-a", "false-a", "true-b", "false-b"]
    
    #variables to keep track of rechecking
    first_strict_signature = ""
    first_relaxed_signature = ""
    second_strict_signature = ""
    second_relaxed_signature = ""
    confidence = 0
    vuln = False
    first_strict_vuln = False
    first_relaxed_vuln = False
    
    for j in range(2):
      if j == 1 and not (first_strict_vuln or first_relaxed_vuln):
          break
      payloads = []
      requests = []
      responses = []
      conditions = []
      sc = SimilarityChecker()
      self.Scnr.Trace("<i<br>>")
      for i in range(len(trailers)):
        payload = "{0}{1} {2} {3}".format(prefix, quote, operator, trailers[i].replace("<q>", quote))
        self.Scnr.RequestTrace("  Request Key: '{0}' - Injecting {1}".format(keys[i], payload))
        res = self.Scnr.Inject(payload)
        payloads.append(payload)
        conditions.append(trailers[i].replace("<q>", quote))
        requests.append(self.Scnr.InjectedRequest.GetClone())
        responses.append(res)
        sc.Add(keys[i], res)
        self.Scnr.ResponseTrace(" ==> Code-{0} Length-{1}".format(res.Code, res.BodyLength))
      
      sc.Check()
      
      self.Scnr.Trace("<i<br>>  The responses are analyzed for similarity based grouping to determine if injection succeeded.")
      self.Scnr.Trace("  Analysis Results:")
      self.Scnr.Trace("  Strict Groups Signature: {0}".format(sc.StrictGroupsSignature))
      self.Scnr.Trace("  Relaxed Groups Signature: {0}".format(sc.RelaxedGroupsSignature))
  
      if j == 0:				
        first_strict_signature = sc.StrictGroupsSignature
        first_relaxed_signature = sc.RelaxedGroupsSignature
        
        if self.IsBlindBoolInjectableGroupingCheck(sc.StrictGroups):
          self.Scnr.Trace("  <i<b>>Strict Grouping indicates that injection succeeded. Rechecking to confirm.<i</b>>")
          if j == 0:
            first_strict_vuln = True
        else:
          self.Scnr.Trace("  Strict Grouping does not indicates that injection succeeded.")
        
        if self.IsBlindBoolInjectableGroupingCheck(sc.RelaxedGroups):
          self.Scnr.Trace("  <i<b>>Relaxed Grouping indicates that injection succeeded. Rechecking to confirm.<i</b>>")
          if j == 0:
            first_relaxed_vuln = True
        else:
          self.Scnr.Trace("  Relaxed Grouping does not indicates that injection succeeded.")
      else:
        second_strict_signature = sc.StrictGroupsSignature
        second_relaxed_signature = sc.RelaxedGroupsSignature
        vuln = False
        
        if first_strict_vuln and first_strict_signature == second_strict_signature:
          vuln = True
          confidence = confidence + 1
          self.Scnr.Trace("  <i<cr>>Even the second time Strict Grouping indicates that injection succeeded.<i</cr>>")
        else:
          self.Scnr.Trace("  Strict Grouping does not indicate that injection succeeded.")
        
        if first_relaxed_vuln and first_relaxed_signature == second_relaxed_signature:
          vuln = True
          confidence = confidence + 1
          self.Scnr.Trace("  <i<cr>>Even the second time Relaxed Grouping indicates that injection succeeded.<i</cr>>")
        else:
          self.Scnr.Trace("  Relaxed Grouping does not indicate that injection succeeded.")
        
        if vuln:
          self.RequestTriggers.extend(payloads)
          self.TriggerRequests.extend(requests)
          self.TriggerResponses.extend(responses)
          for i in range(len(payloads)):
            self.ResponseTriggers.append("")
            if i == 0 or i == 2:
                self.RequestTriggerDescs.append("The payload in this request contains the conditional operator '{0}' followed by the SQL condition {1} which evaluates to true. The payload is {2}".format(operator, conditions[i], payloads[i]))
            else:
                self.RequestTriggerDescs.append("The payload in this request contains the conditional operator '{0}' followed by the SQL condition {1} which evaluates to false. The payload is {2}".format(operator, conditions[i], payloads[i]))       
          self.ResponseTriggerDescs.append("This response is the result of the first boolean true condition based payload. This response is equal to the response of the second boolean true condition payload and different from the responses of the boolean false condition payloads.")
          self.ResponseTriggerDescs.append("This response is the result of the first boolean false condition based payload. This response is equal to the response of the second boolean false condition payload and different from the responses of the boolean true condition payloads.")
          self.ResponseTriggerDescs.append("This response is the result of the second boolean true condition based payload. This response is equal to the response of the first boolean true condition payload and different from the responses of the boolean false condition payloads.")
          self.ResponseTriggerDescs.append("This response is the result of the second boolean false condition based payload. This response is equal to the response of the first boolean false condition payload and different from the responses of the boolean true condition payloads.")
          self.TriggerCount = self.TriggerCount + 4
          reason = self.GetBlindBoolReason(payloads, operator, self.TriggerCount)
          self.reasons.append(reason)
          return confidence
    return 0
  
  def IsBlindBoolInjectableGroupingCheck(self, groups):
    match = 0
    if len(groups) == 2:
      for group in groups:
        if group.Count == 2:
          match = 0
          if group.HasKey("true-a") and group.HasKey("true-b"):
            match = 1
          elif group.HasKey("false-a") and group.HasKey("false-b"):
            match = 1
    
    if match > 0:
      return True
    else:
      return False
  
  def CheckBlindTime(self):
    score = 0
    self.Scnr.Trace("<i<br>><i<h>>Checking for Time based Injection:<i</h>>")
    self.Scnr.Trace("<i<br>> Sending three requests to get a baseline of the response time for time based check:")
    min_delay = -1
    max_delay = 0
    time = 10000
    base_line_delays = []
    avg_time = 0
    for i in range(3):
      res = self.Scnr.Inject()
      avg_time = avg_time + res.RoundTrip
      base_line_delays.append("  {0}) Response time is - {1} ms".format(i+1, res.RoundTrip))
      if res.RoundTrip > max_delay:
        max_delay = res.RoundTrip
      if res.RoundTrip < min_delay or min_delay == -1:
        min_delay = res.RoundTrip
    self.Scnr.Trace("<i<br>>".join(base_line_delays))
    avg_time = avg_time/3
    
    if min_delay > 5000:
      time = ((max_delay + min_delay) / 1000) + 1
    else:
      time = ((max_delay + 5000) / 1000) + 1
    
    self.Scnr.Trace("<i<br>> Response Times: Minimum - {0}ms. Maximum - {1}ms.".format(min_delay, max_delay))
    self.Scnr.Trace("<i<br>> <i<b>>Testing with delay time of {0}ms.<i</b>>".format(time * 1000))
    for inj_str in self.time_check:
      payload = inj_str.replace("__TIME__", str(time))
      score = score + self.InjectAndCheckBlindDelay(payload, time, avg_time)
    
    return score
  
  def InjectAndCheckBlindDelay(self, payload, time, avg_time):
    for i in range(2):
      self.Scnr.RequestTrace("  Injecting {0}".format(payload))
      res = self.Scnr.Inject(payload)
      res_trace = "	==> Code-{0} Length-{1} Time-{2}ms.".format(res.Code, res.BodyLength, res.RoundTrip)
      if i == 0:
        if res.RoundTrip >= (time * 1000):
          self.Scnr.ResponseTrace("{0} <i<b>>Delay Observed! Rechecking the result with the same Injection string<i</b>>".format(res_trace))
        else:
          self.Scnr.ResponseTrace("{0} No Time Delay.".format(res_trace))
          break
      elif i == 1:
        if res.RoundTrip >= (time * 1000):
          self.Scnr.ResponseTrace("{0} <i<br>><i<cr>>Delay Observed Again! Indicates Presence of SQL Injection<i</cr>>".format(res_trace))
          
          self.RequestTriggers.append(payload)
          self.RequestTriggerDescs.append("The payload in this request contains a SQL query snippet which if executed will cause a delay of {0} milliseconds. The payload is {1}".format(time * 1000, payload))
          self.TriggerRequests.append(self.Scnr.InjectedRequest.GetClone())
          
          self.ResponseTriggers.append("")
          self.ResponseTriggerDescs.append("It took {0} milliseconds to get this response. It took so long because of the {1} milliseconds delay caused by the payload.".format(res.RoundTrip, time * 1000))
          self.TriggerResponses.append(res)
          
          self.TriggerCount = self.TriggerCount + 1
          reason = self.GetBlindTimeReason(payload, time * 1000, res.RoundTrip, avg_time, self.TriggerCount)
          self.reasons.append(reason)
          #self.ReportSQLInjection()
          return 1
        else:
          self.Scnr.ResponseTrace("{0} <i<b>>Time Delay did not occur again!<i</b>>".format(res_trace))
    
    return 0
  
  def ReportSQLInjection(self, Confidence):
    self.Scnr.SetTraceTitle("SQLi Found", 100)
    PR = Finding(self.Scnr.InjectedRequest.BaseUrl)
    PR.Title = "SQL Injection Detected"
    PR.Summary = "SQL Injection has been detected in the '{0}' parameter of the {1} section of the request.<i<br>><i<br>>{2}".format(self.Scnr.InjectedParameter, self.Scnr.InjectedSection, self.GetSummary())
    for reason in self.reasons:
      PR.AddReason(reason)
      
    for i in range(len(self.RequestTriggers)):
      PR.Triggers.Add(self.RequestTriggers[i], self.RequestTriggerDescs[i], self.TriggerRequests[i], self.ResponseTriggers[i], self.ResponseTriggerDescs[i], self.TriggerResponses[i])
    PR.Type = FindingType.Vulnerability
    PR.Severity = FindingSeverity.High
    PR.Confidence = Confidence
    self.Scnr.AddFinding(PR)
  
  def ReportSQLError(self, Errors):
    self.Scnr.SetTraceTitle("SQL Error Messages Found", 100)
    PR = Finding(self.Scnr.InjectedRequest.BaseUrl)
    PR.Title = "SQL Error Messages Found"
    Summary = "SQL Error Messages have been found in the response when testing the '{0}' parameter of the {1} section of the request. All checks performed to returned negative results so the reason why these error messages appear cannot be determined.<i<br>>".format(self.Scnr.InjectedParameter, self.Scnr.InjectedSection)
    Summary = Summary + "The error messages are:<i<br>>"
    for Error in Errors:
      Summary = Summary + "<i<cr>>{0}<i</cr>><i<br>>".format(Error)
    PR.Summary = Summary
    if len(self.RequestTriggers) > 0:
      PR.Triggers.Add("", "", self.TriggerRequests[0], "\r\n".join(Errors), "The response contained {0} SQL error messages".format(len(Errors)), self.TriggerResponses[0])
    PR.Type = FindingType.Vulnerability
    PR.Severity = FindingSeverity.Medium
    PR.Confidence = FindingConfidence.High
    self.Scnr.AddFinding(PR)

  def SetUp(self):
    err_regex_file = open(Config.Path + "\\plugins\\active\\sql_error_regex.txt")
    err_regex_file.readline()#Ignore the first line containing comments
    error_strings = err_regex_file.readlines()
    err_regex_file.close()
    for err_str in error_strings:
      err_str = err_str.strip()
      if len(err_str) > 0:
        self.error_regex_raw.append(err_str)
        self.error_regex.append(re.compile(err_str, re.I))
    time_check_file = open(Config.Path + "\\plugins\\active\\sql_time_check.txt")
    time_check_file.readline()#Ignore the first line containing comments
    time_check_temp = time_check_file.readlines()
    time_check_file.close()
    for tct in time_check_temp:
      tct = tct.strip()
      if len(tct) > 0:
        self.time_check.append(tct)

  def GetSummary(self):
    Summary = "SQL Injection is an issue where it is possible execute SQL queries on the database being used on the server-side. For more details on this issue refer <i<cb>>https://www.owasp.org/index.php/SQL_Injection<i</cb>><i<br>><i<br>>"
    return Summary
  
  def GetErrorReason(self, payload, errors, Trigger):
    payload  = Tools.EncodeForTrace(payload)
    
    #Reason = "IronWASP sent <i>'abcd<i> as payload to the application and the response that came back had the error message <i>Incorrect SQL syntax</i>. "
    Reason = "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application and the response that came back ".format(payload)
    
    if len(errors) == 1:
      Reason = Reason + "had the error message <i<hlg>>{0}<i</hlg>>. ".format(errors[0])
    else:
      Reason = Reason + "had the error messages "
      for i in range(len(errors)):
        if i == (len(errors) - 1):
          Reason = Reason + " and "
        elif i > 0:
          Reason = Reason + " , "
        Reason = Reason + "<i<hlg>>{0}<i</hlg>>".format(errors[i])
      Reason = Reason + "."
    
    Reason = Reason + "This error message is usually associated with SQL query related errors and it appears that the payload was able to break out of the data context and cause this error. "
    Reason = Reason + "This is an indication of SQL Injection."
    
    ReasonType = "Error"
    
    #False Positive Check
    FalsePositiveCheck = "Manually analyze the response received for the payload and confirm if the error message actually is because of some SQL related exception on the server-side. Try sending the same request without the payload and check if the error goes away."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, Trigger, FalsePositiveCheck)
    return FR

  def GetBlindMathAddReason(self, payloads, first_sum, second_sum, first_group, second_group, Trigger):
    Reason = "IronWASP sent six payload to the application with SQL code snippets in them.<i<br>>"
    
    ids = ["A", "B", "C", "D", "E", "F"]
    
    #Payload A - <i>4+1<i>
    #Payload B - <i>3+2<i>
    #Payload C - <i>4+5<i>
    #Payload D - <i>3+6<i>
    #Payload E - <i>4+a<i>
    #Payload F - <i>4+b<i>
    
    for i in range(len(ids)):
      payloads[i] = Tools.EncodeForTrace(payloads[i])
      Reason = Reason + "Payload {0} - <i<hlg>>{1}<i</hlg>><i<br>>".format(ids[i], payloads[i])
    
    #Reason = Reason + "Payload A and B is the addition of two numbers whose sum 5. "
    Reason = Reason + "Payload A and B is the addition of two numbers whose sum would be <i<hlg>>{0}<i</hlg>>. ".format(first_sum)
    #Reason = Reason + "Payload C and D is also the addition of two numbers whose sum would be 9. "
    Reason = Reason + "Payload C and D is also the addition of two numbers whose sum would be <i<hlg>>{0}<i</hlg>>. ".format(second_sum)
    Reason = Reason + "Payload E and F are invalid addition attempts as a number is being added to a string.<i<br>>"
      
    if len(first_group) == 2:
      Reason = Reason + "The response for Payload A and B is similar to each other and is different from Payloads C, D, E and F. "
      Reason = Reason + "This indicates that the application actually performed the addition of the two numbers in the Payload A and B. "
      Reason = Reason + "Since they add up to the same value their responses are similar. Payloads C and D add up to different values. "
      Reason = Reason + "Payload E and F are invalid addition attempts. If the application was not actually performing addition then all six payload should have returned very similar responses. "
    else:
      Reason = Reason + "The response for Payload A, B, C and D are similar to each other and is different from Payloads E and F. "
      Reason = Reason + "This indicates that the application actually performed the addition of the two numbers in the Payload A, B, C and D. "
      Reason = Reason + "Since in all four cases the addition is a valid SQL syntax their responses are similar. "
      Reason = Reason + "Payload E and F are invalid addition attempts so their responses are different. If the application was not actually performing addition then all six payloads should have returned very similar responses. "
    Reason = Reason + "Therefore this indicates that SQL syntax from the payload is executed as part of the SQL query on the server."
    
    ReasonType = "MathAdd"
    
    #False Positive Check
    FalsePositiveCheck = "Manually analyze the responses received for the six payloads and confirm if the type of similarity explained above actually exists in them. Try resending the same payloads again but with different numbers and check if this behaviour is repeated."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, [Trigger-5, Trigger-4, Trigger-3, Trigger-2, Trigger-1, Trigger], FalsePositiveCheck)
    return FR

  def GetBlindMathSubtractReason(self, payloads, first_diff, second_diff, first_group, second_group, Trigger):
    Reason = "IronWASP sent six payload to the application with SQL code snippets in them.<i<br>>"
    
    ids = ["A", "B", "C", "D", "E", "F"]
    
    #Payload A - <i>4-1<i>
    #Payload B - <i>5-2<i>
    #Payload C - <i>7-5<i>
    #Payload D - <i>8-6<i>
    #Payload E - <i>4-a<i>
    #Payload F - <i>4-b<i>

    
    for i in range(len(ids)):
      payloads[i] = Tools.EncodeForTrace(payloads[i])
      Reason = Reason + "Payload {0} - <i<hlg>>{1}<i</hlg>><i<br>>".format(ids[i], payloads[i])
    
    #Reason = Reason + "Payload A and B is the subtraction of two numbers whose difference is 3. "
    Reason = Reason + "Payload A and B is the subtraction of two numbers whose difference is <i<hlg>>{0}<i</hlg>>. ".format(first_diff)
    #Reason = Reason + "Payload C and D is also the subtraction of two numbers whose difference would be 2. "
    Reason = Reason + "Payload C and D is also the subtraction of two numbers whose difference would be <i<hlg>>{0}<i</hlg>>. ".format(second_diff)
    Reason = Reason + "Payload E and F are invalid subtraction attempts as a string is being deducted from a number.<i<br>>"
    
    if len(first_group) == 2:
      Reason = Reason + "The response for Payload A and B is similar to each other and is different from Payloads C, D, E and F. "
      Reason = Reason + "This indicates that the application actually performed the subtraction of the two numbers in the Payload A and B. "
      Reason = Reason + "Since their differnce is the same their responses are similar. Payloads C and D have a different difference values. "
      Reason = Reason + "Payload E and F are invalid subtraction attempts. If the application was not actually performing subtraction then all six payload should have returned very similar responses. "
    else:
      Reason = Reason + "The response for Payload A, B, C and D are similar to each other and is different from Payloads E and F. "
      Reason = Reason + "This indicates that the application actually performed the subtraction of the two numbers in the Payload A, B, C and D. "
      Reason = Reason + "Since in all four cases the substration is a valid SQL syntax their responses are similar. "
      Reason = Reason + "Payload E and F are invalid subtraction attempts so their responses are different. If the application was not actually performing subtraction then all six payloads should have returned very similar responses. "
    Reason = Reason + "Therefore this indicates that SQL syntax from the payload is executed as part of the SQL query on the server."
    
    ReasonType = "MathSubtract"
    
    #False Positive Check
    FalsePositiveCheck = "Manually analyze the responses received for the six payloads and confirm if the type of similarity explained above actually exists in them. Try resending the same payloads again but with different numbers and check if this behaviour is repeated."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, [Trigger-5, Trigger-4, Trigger-3, Trigger-2, Trigger-1, Trigger], FalsePositiveCheck)
    return FR

  def GetBlindConcatReason(self, payloads, db, Trigger):
    Reason = "IronWASP sent three payloads to the application with SQL code snippets in them.<i<br>>"
    
    ids = ["A", "B", "C"]
    
    #Payload A - <i>a'||'b<i>
    #Payload B - <i>a'+'b<i>
    #Payload C - <i>a' 'b<i>
    
    for i in range(len(ids)):
      payloads[i] = Tools.EncodeForTrace(payloads[i])
      Reason = Reason + "Payload {0} - <i<hlg>>{1}<i</hlg>><i<br>>".format(ids[i], payloads[i])
      
    Reason = Reason + "Payload A is trying to concatenate two strings as per the SQL syntax of Oracle database servers. "
    Reason = Reason + "Payload B is trying to concatenate the same two strings as per SQL syntax of MS SQL database servers. "
    Reason = Reason + "Payload C is trying to concatenate the same two strings as per the SQL syntax of MySQL database servers.<i<br>>"
    
    same = []
    diff = ""
    
    #keys = [ "Oracle", "MS SQL", "MySQL"]
    
    if db == "Oracle":
      diff = "A"
      same = ["B", "C"]
    elif db == "MS SQL":
      diff = "B"
      same = ["A", "C"]
    elif db == "MySQL":
      diff = "C"
      same = ["A", "B"]
    else:
      return ""
    
    #Reason = Reason + "The response for Payload A and B were similar to each other and is different from the response recieved for Payloads C. "
    Reason = Reason + "The response for Payload {0} and {1} were similar to each other and is different from the response received for Payloads {2}. ".format(same[0], same[1], diff)
    #Reason = Reason + "This indicates that the application was actually trying to perform the string concatenation on the server-side and that the backend database in use is MySQL. "
    Reason = Reason + "This indicates that the application was actually trying to perform the string concatenation on the server-side and that the backend database in use is <i<hlg>>{0}<i</hlg>>. ".format(db)
    #Reason = Reason + "Since incase of MySQL Payloads A & B would have simply thrown an invalid SQL syntax exception their responses are similar. "
    Reason = Reason + "Since incase of <i<hlg>>{0}<i</hlg>> database server Payloads {0} & {1} would have simply thrown an invalid SQL syntax exception their responses are similar. ".format(db, same[0], same[1])
    #Reason = Reason + "And Payload C would have executed without this error and so its response was different than the other two.<i<br>>"
    Reason = Reason + "And Payload {0} would have executed without this error and so its response was different than the other two.<i<br>>".format(diff)
    
    Reason = Reason + "If the application was not actually performing the concatenation then all three payload should have received very similar responses. "
    Reason = Reason + "Therefore this indicates that SQL syntax from the payload is executed as part of the SQL query on the server."

    ReasonType = "Concat"
    
    #False Positive Check
    FalsePositiveCheck = "Manually analyze the responses received for the three payloads and confirm if the type of similarity explained above actually exists in them. Try resending the same payloads again but with different strings and check if this behaviour is repeated."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, [Trigger-2, Trigger-1, Trigger], FalsePositiveCheck)
    return FR

  def GetBlindBoolReason(self, payloads, bool_cond, Trigger):
    bool_cond = bool_cond.upper()
    
    Reason = "IronWASP sent four payloads to the application with SQL code snippets in them.<i<br>>"
    
    ids = ["A", "B", "C", "D"]
    #Payload A - <i>a' or 8=8--<i>
    #Payload B - <i>a' or 7=5--<i>
    #Payload C - <i>a' or 6=6--<i>
    #Payload D - <i>a' or 4=6--<i>
    
    for i in range(len(ids)):
      payloads[i] = Tools.EncodeForTrace(payloads[i])
      Reason = Reason + "Payload {0} - <i<hlg>>{1}<i</hlg>><i<br>>".format(ids[i], payloads[i])
    
    #Reason = Reason + "Payload A and C have a boolean condition after the OR keyword that will evaluate to true. The boolean condition in Payload B and D would evaluate to false.".format(payload)
    Reason = Reason + "Payload A and C have a boolean condition after the <i<hlg>>{0}<i</hlg>> keyword that will evaluate to true. ".format(bool_cond)
    Reason = Reason + "The boolean condition in Payload B and D would evaluate to false.<i<br>>"
    
    Reason = Reason + "The response for Payload A and C were similar to each other and were different from the response received for Payload B and D. "
    Reason = Reason + "This indicates that the application was actually evaluating the boolean condition in the payloads. "
    Reason = Reason + "So since Payload A and C both has a true boolean condition their responses are similar, C and D had a false boolean condition.<i<br>>"
    
    Reason = Reason + "If the application was not actually evaluating the boolean condition then all four payload should have returned very similar responses. "
    Reason = Reason + "Therefore this indicates that SQL syntax from the payload is executed as part of the SQL query on the server."
    
    ReasonType = "Bool"
    
    #False Positive Check
    FalsePositiveCheck = "Manually analyze the responses received for the four payloads and confirm if the type of similarity explained above actually exists in them. Try resending the same payloads again but with values in the boolean expression and check if this behaviour is repeated."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, [Trigger-3, Trigger-2, Trigger-1, Trigger], FalsePositiveCheck)
    return FR

  def GetBlindTimeReason(self, payload, delay_time, res_time, normal_time, Trigger):
    payload  = Tools.EncodeForTrace(payload)
    
    #Reason = "IronWASP sent <i>' and pg_sleep(5)--</i> as payload to the application. "
    Reason = "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application. ".format(payload)
    #Reason = Reason + "This payload has a small snippet of SQL code that will cause the database server to sleep for 5000 milliseconds. "
    Reason = Reason + "This payload has a small snippet of SQL code that will cause the database server to sleep for <i<hlg>>{0}<i</hlg>> milliseconds. ".format(delay_time)
    #Reason = Reason + "If this code is executed then the application will return the response 5000 milliseconds later than usual. "
    Reason = Reason + "If this code is executed then the application will return the response <i<hlg>>{0}<i</hlg>> milliseconds later than usual. ".format(delay_time)
    #Reason = Reason + "After the payload was injected the response from the application took <i>6783</i> milliseconds. "
    Reason = Reason + "After the payload was injected the response from the application took <i<hlg>>{0}<i</hlg>> milliseconds. ".format(res_time)
    #Reason = Reason + "Normally this particular request is processed at around <i>463</i> milliseconds. "
    Reason = Reason + "Normally this particular request is processed at around <i</hlg>>{0}<i</hlg>> milliseconds. ".format(normal_time)
    Reason = Reason + "This indicates that the injected SQL code snippet could have been executed on the server-side."
    
    ReasonType = "TimeDelay"
    
    #False Positive Check
    FalsePositiveCheck = "To check if this was a valid case or a false positive you can manually inject the same payload but by changing the number of seconds of delay to different values. Then you can observe if the time taken for the response to be returned is affected accordingly."
    FalsePositiveCheck = FalsePositiveCheck + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    
    FR = FindingReason(Reason, ReasonType, Trigger, FalsePositiveCheck)
    return FR


p = SQLInjection()
p.SetUp()
ActivePlugin.Add(p.GetInstance())
