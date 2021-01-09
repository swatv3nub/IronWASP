from IronWASP import *

class Parameter():
    id_counter = 0
    
    def __init__(self, name, section):
        Parameter.id_counter += 1
        self.id = Parameter.id_counter
        self.name = name
        self.values = ValuesList()
        self.sections = [section]

class Value():
    id_counter = 0
    
    def __init__(self, name, value, section, source, log_id):
        Value.id_counter += 1
        self.id = Value.id_counter
        self.value = value
        self.parameter_name = name
        self.section = section
        self.proxy_log_ids = []
        self.probe_log_ids = []
        if source == "Proxy":
            self.proxy_log_ids.append(log_id)
        elif source == "Probe":
            self.probe_log_ids.append(log_id)
        self.md5 = Tools.MD5(value)
        self.sha1 = Tools.SHA1(value)
        self.sha256 = Tools.SHA256(value)
        self.sha384 = Tools.SHA384(value)
        self.sha512 = Tools.SHA512(value)

    def is_same(self, val):
        if self.id == val.id:
            return True
        else:
            return False
    
    def is_equal(self, val):
        if self.parameter_name == val.parameter_name and self.value == val.value and self.section == val.section:
            return True
        else:
            return False

class UniversalParametersList():
    def __init__(self):
        self.internal_dict = {}
    
    def add_param(self, base_url, name, value, section, log_id, source):
        if not self.internal_dict.has_key(base_url):
            self.internal_dict[base_url] = ParametersList()
        self.internal_dict[base_url].add_param(name, value, section, log_id, source)
    
    def get_value(self, base_url, name, value, section, log_id, source):
        if self.internal_dict.has_key(base_url):
            return self.internal_dict[base_url].get_value(name, value, section, log_id, source)
    
    def get_base_urls(self):
        return self.internal_dict.keys()
    
    def get_parameters_list(self, base_url):
        if self.internal_dict.has_key(base_url):
            return self.internal_dict[base_url]
    
class ParametersList():
    def __init__(self):
        self.internal_dict = {}
    
    def add_param(self, name, value, section, log_id, source):
        found_match = False
        for p_id in self.internal_dict.keys():
            if self.internal_dict[p_id].name == name:
                found_match = True
                matched_param = self.internal_dict[p_id]
                if matched_param.sections.count(section) == 0:
                    matched_param.sections.append(section)
                matched_param.values.add_value(name, value, section, log_id, source)
                break
        if not found_match:
            new_param = Parameter(name, section)
            new_param.values.add_value(name, value, section, log_id, source)
            self.internal_dict[new_param.id] = new_param
    
    def get_value(self, name, value, section, log_id, source):
        for p_id in self.internal_dict.keys():
            if self.internal_dict[p_id].name == name:
                return self.internal_dict[p_id].values.get_value(name, value, section, log_id, source)
    
    def get_ids(self):
        return self.internal_dict.keys()
    
    def get_parameter(self, id):
        if self.internal_dict.has_key(id):
            return self.internal_dict[id]

class ValuesList():
    def __init__(self):
        self.internal_dict = {}
    
    def add_value(self, name, value, section, log_id, source):
        found_match = False
        for v_id in self.internal_dict.keys():
            current_value = self.internal_dict[v_id]
            if current_value.parameter_name == name and current_value.value == value and current_value.section == section:
                found_match = True
                if source == "Proxy":
                    if current_value.proxy_log_ids.count(log_id) == 0:
                        current_value.proxy_log_ids.append(log_id)
                elif source == "Probe":
                    if current_value.probe_log_ids.count(log_id) == 0:
                        current_value.probe_log_ids.append(log_id)
                break
        if not found_match:
            new_value = Value(name, value, section, source, log_id)
            self.internal_dict[new_value.id] = new_value
    
    def get_value(self, name, value, section, log_id, source):
        for v_id in self.internal_dict.keys():
            current_value = self.internal_dict[v_id]
            if current_value.parameter_name == name and current_value.value == value and current_value.section == section:
                if source == "Proxy":
                    if current_value.proxy_log_ids.count(log_id) > 0:
                        return current_value
                elif source == "Probe":
                    if current_value.probe_log_ids.count(log_id) > 0:
                        return current_value
    
    def get_ids(self):
        return self.internal_dict.keys()
    
    def get_value_with_id(self, id):
        if self.internal_dict.has_key(id):
            return self.internal_dict[id]

class EncodedValue():
    id_counter = 0
    
    def __init__(self, value, decoded_result, log_ids, parameter_name):
        EncodedValue.id_counter += 1
        self.id = EncodedValue.id_counter
        self.value = value
        self.base64_decoded_value = decoded_result["Base64"]
        self.hex_decoded_value = decoded_result["Hex"]
        self.log_ids = [log_ids]
        self.parameter_names = [parameter_name]
    
    def add_log_ids(self, log_ids):
        self.log_ids.extend(log_ids)
    
    def add_parameter_name(self, parameter_name):
        if self.parameter_names.count(parameter_name) == 0:
            self.parameter_names.append(parameter_name)

class EncodedValuesList():
    def __init__(self):
        self.internal_dict = {}
    
    def add(self, value, decoded_result):
        found_match = False
        for v_id in self.internal_dict.keys():
            current_encoded_value = self.internal_dict[v_id]
            if current_encoded_value.value == value.value:
                current_encoded_value.add_log_ids(value.proxy_log_ids)
                current_encoded_value.add_parameter_name(value.parameter_name)
                found_match = True
                break
        if not found_match:
            new_encoded_value = EncodedValue(value.value, decoded_result, value.proxy_log_ids, value.parameter_name)
            self.internal_dict[new_encoded_value.id] = new_encoded_value
    
    def get_ids(self):
        return self.internal_dict.keys()
    
    def get(self, id):
        if self.internal_dict.has_key(id):
            return self.internal_dict[id]

class UniversalEncodedValuesList():
    def __init__(self):
        self.internal_dict = {}
    
    def add(self, base_url, value, decoded_result):
        if not self.internal_dict.has_key(base_url):
            self.internal_dict[base_url] = EncodedValuesList()
        self.internal_dict[base_url].add(value, decoded_result)
    
    def get_list(self, base_url):
        if self.internal_dict.has_key(base_url):
            return self.internal_dict[base_url]
    
    def get_base_urls(self):
        return self.internal_dict.keys()

class HashedValue():
    id_counter = 0
    
    def __init__(self, value, cracked_value, hash_type, log_ids, parameter_name):
        HashedValue.id_counter += 1
        self.id = HashedValue.id_counter
        self.value = value#hashed value
        self.cracked_value = cracked_value
        self.hash_type = hash_type#md5, sha etc
        self.log_ids = [log_ids]
        self.parameter_names = [parameter_name]
    
    def add_log_ids(self, log_ids):
        self.log_ids.extend(log_ids)
    
    def add_parameter_name(self, parameter_name):
        if self.parameter_names.count(parameter_name) == 0:
            self.parameter_names.append(parameter_name)
    

class HashedValuesList():
    def __init__(self):
        self.internal_dict = {}
       
    def add(self, value, cracked_value, hash_type):
        found_match = False
        for v_id in self.internal_dict.keys():
            current_hashed_value = self.internal_dict[v_id]
            if current_hashed_value.value == value.value:
                current_hashed_value.add_log_ids(value.proxy_log_ids)
                current_hashed_value.add_parameter_name(value.parameter_name)
                found_match = True
                break
        if not found_match:
            new_hashed_value = HashedValue(value.value, cracked_value, hash_type, value.proxy_log_ids, value.parameter_name)
            self.internal_dict[new_hashed_value.id] = new_hashed_value
    
    def get_ids(self):
        return self.internal_dict.keys()
    
    def get(self, id):
        if self.internal_dict.has_key(id):
            return self.internal_dict[id]

class UniversalHashedValuesList():
    def __init__(self):
        self.internal_dict = {}
    
    def add(self, base_url, value, cracked_value, hash_type):
        if not self.internal_dict.has_key(base_url):
            self.internal_dict[base_url] = HashedValuesList()
        self.internal_dict[base_url].add(value, cracked_value, hash_type)
    
    def get_list(self, base_url):
        if self.internal_dict.has_key(base_url):
            return self.internal_dict[base_url]
    
    def get_base_urls(self):
        return self.internal_dict.keys()

class StoredReflectionsItem():
    id_counter = 0
    
    def __init__(self, value, sess):
        StoredReflectionsItem.id_counter += 1
        self.id = StoredReflectionsItem.id_counter
        self.parameter_name = value.parameter_name
        self.value = value.value
        self.request_log_ids = []
        self.request_log_ids.extend(value.proxy_log_ids)
        self.response_log_ids = [sess.GetId()]
    
    def add_log_ids(self, req_log_ids, res_log_id):
        for req_log_id in req_log_ids:
            if self.request_log_ids.count(req_log_id) == 0:
                self.request_log_ids.append(req_log_id)
        if self.response_log_ids.count(res_log_id) == 0:
            self.response_log_ids.append(res_log_id)
    
class StoredReflectionsList():
    def __init__(self):
        self.internal_dict = {}
       
    def add(self, value, sess):
        found_match = False
        for i_id in self.internal_dict.keys():
            current_sr_item = self.internal_dict[i_id]
            if current_sr_item.parameter_name == value.parameter_name and current_sr_item.value == value.value:
                current_sr_item.add_log_ids(value.proxy_log_ids, sess.GetId())
                found_match = True
                break
        if not found_match:
            new_sr_item = StoredReflectionsItem(value, sess)
            self.internal_dict[new_sr_item.id] = new_sr_item
    
    def get_ids(self):
        return self.internal_dict.keys()
    
    def get(self, id):
        if self.internal_dict.has_key(id):
            return self.internal_dict[id]

class UniversalStoredReflectionsList():
    def __init__(self):
        self.internal_dict = {}
    
    def add(self, base_url, value, sess):
        if not self.internal_dict.has_key(base_url):
            self.internal_dict[base_url] = StoredReflectionsList()
        self.internal_dict[base_url].add(value, sess)
    
    def get_list(self, base_url):
        if self.internal_dict.has_key(base_url):
            return self.internal_dict[base_url]
    
    def get_base_urls(self):
        return self.internal_dict.keys()



