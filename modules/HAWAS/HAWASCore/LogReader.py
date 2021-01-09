from IronWASP import *
import re

class Reader:
    
    def __init__(self, hawas):
        self.hawas = hawas
        self.md5_re = re.compile(r"([a-fA-F\d]{32})")
        self.sha1_re = re.compile(r"([a-fA-F\d]{40})")
        self.sha256_re = re.compile(r"([a-fA-F\d]{64})")
        self.sha384_re = re.compile(r"([a-fA-F\d]{96})")
        self.sha512_re = re.compile(r"([a-fA-F\d]{128})")
    
    def read_logs(self):
        try:
            for log_source in self.hawas.log_sources:
                for i in range(1, self.get_last_log_id(log_source) + 1):
                    try:
                        self.hawas.show_status("Analyzing log ID {0}".format(i))
                        sess = self.get_session(log_source, i)
                        self.analyze_session(sess, log_source)
                        self.read_session(sess, log_source)
                    except Exception as e:
                        if e.clsException.GetType().Name != "ThreadAbortException":
                            #IronException.Report("Error in HAWAS", e.message)
                            Tools.Trace("read_logs_exception", e.message)
                            self.hawas.show_status("Error reading log ID {0}".format(i))
            #self.display_results()
            self.hawas.show_status("Trying to crack any hashes found in logs...")
            self.crack_hashed_values()            
            self.hawas.show_status("Done!")
            self.hawas.end_hawas()
        except Exception as e:
            if e.clsException.GetType().Name != "ThreadAbortException":
                raise e

    def read_session(self, sess, source):
        req = sess.Request
        res = sess.Response
        self.read_params(req, res, source)
    
    def read_params(self, req, res, source):
        self.add_url_path_params(req, req.GetId(), source)
        self.add_params(req.BaseUrl, req.Query, "Query", req.GetId(), source)
        self.add_params(req.BaseUrl, req.Body, "Body", req.GetId(), source)
        self.add_params(req.BaseUrl, req.Cookie, "Cookie", req.GetId(), source)
        self.add_params(req.BaseUrl, req.Headers, "Request Header", req.GetId(), source)
        if res:
            self.add_params(req.BaseUrl, res.Headers, "Response Header", req.GetId(), source)
            self.add_html_form_params(req.BaseUrl, res, req.GetId(), source)
            self.add_set_cookie_params(req.BaseUrl, res, req.GetId(), source)
    
    def add_params(self, base_url, params, section, log_id, source):
        try:
            names = params.GetNames()
            for name in names:
                for val in params.GetAll(name):
                    self.hawas.params.add_param(base_url, name, val, section, log_id, source)
                    value_obj = self.hawas.params.get_value(base_url, name, val, section, log_id, source)
                    self.analyze_value(base_url, value_obj)
        except Exception as e:
            Tools.Trace("LogReader - add_params", e.message)
    
    def add_url_path_params(self, req, log_id, source):
        try:
            if len(req.File) == 0 and req.Query.Count == 0:
                for value in req.UrlPathParts:
                    self.hawas.params.add_param(req.BaseUrl, "", value, "Url Path Part", log_id, source)
                    value_obj = self.hawas.params.get_value(req.BaseUrl, "", value, "Url Path Part", log_id, source)
                    self.analyze_value(req.BaseUrl, value_obj)
        except Exception as e:
            Tools.Trace("LogReader - add_url_path_params", e.message)

    def add_html_form_params(self, base_url, res, log_id, source):
        if not res.IsHtml:
            return
        try:
            input_nodes = res.Html.GetNodes("input")
            if not input_nodes:
                return
            for node in input_nodes:
                name = ""
                value = ""
                for attr in node.Attributes:
                    if attr.Name.lower() == "name":
                        name = attr.Value
                    elif attr.Name.lower() == "value":
                        value = attr.Value
                if len(name):# > 0 and len(value) > 0:
                    self.hawas.params.add_param(base_url, name, value, "Form Field", log_id, source)
                    value_obj = self.hawas.params.get_value(base_url, name, value, "Form Field", log_id, source)
                    self.analyze_value(base_url, value_obj)
        except Exception as e:
            Tools.Trace("LogReader - add_html_form_params", e.message)
    
    def add_set_cookie_params(self, base_url, res, log_id, source):
        try:
            for sc in res.SetCookies:
                self.hawas.params.add_param(base_url, sc.Name, sc.Value, "Set-Cookie", log_id, source)
                value_obj = self.hawas.params.get_value(base_url, sc.Name, sc.Value, "Set-Cookie", log_id, source)
                self.analyze_value(base_url, value_obj)
        except Exception as e:
            Tools.Trace("LogReader - add_set_cookie_params", e.message)
    
    def analyze_value(self, base_url, value):
        self.check_encoding(base_url, value)
        self.check_hashing(base_url, value)
       #self.stored_reflections(base_url, value)
    
    def analyze_session(self, sess, log_source):
        self.check_stored_reflection(sess)
    #def display_results(self):
    #    self.hawas.set_host_rows()
    
    def get_last_log_id(self, source):
        if source == "Proxy":
            return Config.LastProxyLogId
        elif source == "Probe":
            return Config.LastProbeLogId
        elif source == "Shell":
            return Config.LastShellLogId
        elif source == "Scan":
            return 1, Config.LastScanLogId
        elif source == "Test":
            return Config.LastTestLogId
        else:
            raise Exception("Invalid Source Specified")

    def get_session(self, source, id):
        if source == "Proxy":
            return Session.FromProxyLog(id)
        elif source == "Probe":
            return Session.FromProbeLog(id)
        elif source == "Shell":
            return Session.FromShellLog(id)
        elif source == "Scan":
            return Session.FromScanLog(id)
        elif source == "Test":
            return Session.FromTestLog(id)
        else:
            raise Exception("Invalid Source Specified")


    def check_encoding(self, base_url, value):
        try:
            if self.hawas.config.encoding_settings.is_section_name_ignored(value.section, value.parameter_name):
                return
            dec_result = self.get_decoded_value(value.value)
            if len(dec_result["Base64"]) > 0 or len(dec_result["Hex"]) > 0:
                self.hawas.encoded_values.add(base_url, value, dec_result)
        except Exception as e:
            Tools.Trace("LogReader - check_encoding", e.message)
    
    def get_decoded_value(self, value):
        dec_val_result = {"Base64": "", "Hex": ""}
        try:
            b64_dec_val = Tools.Base64Decode(value)
            if self.is_ascii(b64_dec_val):
                dec_val_result["Base64"] = b64_dec_val
        except:
            pass
        try:
            if Tools.IsEven(len(value)):
                hex_str = ""
                for i in range(0, len(value), 2):
                    hex_str = hex_str + "%{0}{1}".format(value[i], value[i+1])
                hex_dec_val = Tools.HexDecode(hex_str)
                if self.is_ascii(hex_dec_val):
                    dec_val_result["Hex"] = hex_dec_val
        except:
            pass
        return dec_val_result
    
    def is_ascii(self, value):
        for i in range(len(value)):
            if ord(value[i]) < 32 or ord(value[i]) > 126:
                return False
        return True

    def check_hashing(self, base_url, value):
        try:
            hash_type = self.get_hash_type(value.value)
            if len(hash_type) > 0:
                self.hawas.hashed_values.add(base_url, value, "", hash_type)
        except Exception as e:
            Tools.Trace("LogReader - check_hashing", e.message)            
    
    def get_hash_type(self, value):
        if len(value) == 32 and self.md5_re.match(value):
            return "MD5"
        elif  len(value) == 40 and self.sha1_re.match(value):
            return "SHA1"
        elif  len(value) == 64 and self.sha256_re.match(value):
            return "SHA256"
        elif  len(value) == 96 and self.sha384_re.match(value):
            return "SHA384"
        elif  len(value) == 128 and self.sha512_re.match(value):
            return "SHA512"
        else:
            return ""

    def crack_hashed_values(self):
        checked_values = []
        self.cracked_ids = {}
        try:
            for base_url in self.hawas.params.get_base_urls():
                param_list = self.hawas.params.get_parameters_list(base_url)
                for pid in param_list.get_ids():
                    param = param_list.get_parameter(pid)
                    if self.hawas.config.hashed_settings.is_ignored(param):
                        continue
                    for vid in param.values.get_ids():
                        value = param.values.get_value_with_id(vid)
                        if checked_values.count(value.md5):
                            continue
                        else:
                            checked_values.append(value.md5)
                            self.crack_hashed_values_with_value(value)
        except Exception as e:
            Tools.Trace("LogReader - crack_hashed_values", e.message)
    
    def crack_hashed_values_with_value(self, value):
        try:
            for base_url in self.hawas.hashed_values.get_base_urls():
                hashed_values_list = self.hawas.hashed_values.get_list(base_url)
                for hid in hashed_values_list.get_ids():
                    #check if this hashed value was already cracked
                    if self.cracked_ids.has_key(base_url):
                        if self.cracked_ids[base_url].count(hid)> 0:
                            continue
                    hashed_value = hashed_values_list.get(hid)
                    self.crack_hashed_value_with_value(base_url, hid, hashed_value, value)
        except Exception as e:
            Tools.Trace("LogReader - crack_hashed_values_with_value", e.message)
    
    def crack_hashed_value_with_value(self, base_url, hid, hashed_value, value):
        value_cracked = False
        if hashed_value.hash_type == "MD5":
            if hashed_value.value == value.md5:
                hashed_value.cracked_value = value.value
                value_cracked = True
        elif hashed_value.hash_type == "SHA1":
            if hashed_value.value == value.sha1:
                hashed_value.cracked_value = value.value
                value_cracked = True
        elif hashed_value.hash_type == "SHA256":
            if hashed_value.value == value.sha256:
                hashed_value.cracked_value = value.value
                value_cracked = True
        elif hashed_value.hash_type == "SHA384":
            if hashed_value.value == value.sha384:
                hashed_value.cracked_value = value.value
                value_cracked = True
        elif hashed_value.hash_type == "SHA512":
            if hashed_value.value == value.sha512:
                hashed_value.cracked_value = value.value
                value_cracked = True
        #add this to the list of cracked values
        if value_cracked:
            if not self.cracked_ids.has_key(base_url):
                self.cracked_ids[base_url] = []
            self.cracked_ids[base_url].append(hid)
    
    def check_stored_reflection(self, sess):
        checked_values = []
        try:
            for base_url in self.hawas.params.get_base_urls():
                r = Request(base_url)
                if (sess.Request.Host == r.Host) or sess.Request.Host.endswith(".{0}".format(r.Host)) or r.Host.endswith(".{0}".format(sess.Request.Host)):
                    param_list = self.hawas.params.get_parameters_list(base_url)
                    for pid in param_list.get_ids():
                        param = param_list.get_parameter(pid)
                        if self.hawas.config.stored_reflection_settings.is_ignored(param):
                            continue
                        for vid in param.values.get_ids():
                            value = param.values.get_value_with_id(vid)
                            if self.hawas.config.stored_reflection_settings.is_value_ignored(value):
                                continue
                            if len(value.value) < 6:
                                continue
                            if checked_values.count(value.md5):
                                continue
                            else:
                                checked_values.append(value.md5)
                                self.check_stored_reflection_with_value(base_url, sess, value)
        except Exception as e:
            Tools.Trace("LogReader - check_stored_reflection", e.message)
        return
    
    def check_stored_reflection_with_value(self, base_url, sess, value):
        if self.request_has_value(sess.Request, value.value):
            return
        if sess.Response.BodyString.count(value.value) == 0:
            return
        if self.is_value_reflected(value.value, sess.Response):
            self.hawas.stored_reflections.add(base_url, value, sess)
        
    
    def is_value_reflected(self, val, res):
        safe_val = re.escape(val)
        regex = ".*\W{0}\W.*".format(safe_val)
        if re.search(regex, res.BodyString) == None:
            return False
        else:
            return True
    
    def request_has_value(self, req, value):
        for name in req.Query.GetNames():
            if req.Query.GetAll(name).Contains(value):
                return True
        for name in req.Body.GetNames():
            if req.Body.GetAll(name).Contains(value):
                return True
        for name in req.Cookie.GetNames():
            if req.Cookie.GetAll(name).Contains(value):
                return True
        for name in req.Headers.GetNames():
            if req.Headers.GetAll(name).Contains(value):
                return True
        if len(req.File) == 0 and len(req.Query.GetNames()) == 0:
            if req.UrlPathParts.Contains(value):
                return True
        return False