from IronWASP import *
import re

class Settings:
    
    def __init__(self, hawas):
        self.hawas = hawas
        self.encoding_settings = SectionSetting(self.hawas)
        self.hashed_settings = SectionSetting(self.hawas)
        self.stored_reflection_settings = SectionSetting(self.hawas)
        self.hosts_to_ignore = {}
        self.hosts_to_include = {}
        self.ignore_hosts = False
        self.include_hosts = False
        
        self.encoding_settings.ignore("Request Header", "Accept")
        self.encoding_settings.ignore("Request Header", "Accept-Charset")
        self.encoding_settings.ignore("Request Header", "Accept-Language")
        self.encoding_settings.ignore("Request Header", "Accept-Encoding")
        self.encoding_settings.ignore("Request Header", "Referer")
        self.encoding_settings.ignore("Request Header", "User-Agent")
        self.encoding_settings.ignore("Request Header", "Proxy-Connection")
        self.encoding_settings.ignore("Request Header", "Host")
        self.encoding_settings.ignore("Request Header", "Content-Length")
        self.encoding_settings.ignore("Request Header", "Content-Type")
        
        self.encoding_settings.ignore("Response Header", "If-None-Match")
        self.encoding_settings.ignore("Response Header", "ETag")
        self.encoding_settings.ignore("Response Header", "Date")
        self.encoding_settings.ignore("Response Header", "Server")
        self.encoding_settings.ignore("Response Header", "X-Powered-By")
        self.encoding_settings.ignore("Response Header", "Cache-Control")
        self.encoding_settings.ignore("Response Header", "Content-Type")
        self.encoding_settings.ignore("Response Header", "Content-Length")
        
        self.hashed_settings.ignore("Request Header", "Accept")
        self.hashed_settings.ignore("Request Header", "Accept-Charset")
        self.hashed_settings.ignore("Request Header", "Accept-Language")
        self.hashed_settings.ignore("Request Header", "Accept-Encoding")
        self.hashed_settings.ignore("Request Header", "Referer")
        self.hashed_settings.ignore("Request Header", "User-Agent")
        self.hashed_settings.ignore("Request Header", "Proxy-Connection")
        self.hashed_settings.ignore("Request Header", "Host")
        self.hashed_settings.ignore("Request Header", "Content-Length")
        self.hashed_settings.ignore("Request Header", "Content-Type")
        
        self.hashed_settings.ignore("Response Header", "If-None-Match")
        self.hashed_settings.ignore("Response Header", "ETag")
        self.hashed_settings.ignore("Response Header", "Date")
        self.hashed_settings.ignore("Response Header", "Server")
        self.hashed_settings.ignore("Response Header", "X-Powered-By")
        self.hashed_settings.ignore("Response Header", "Cache-Control")
        self.hashed_settings.ignore("Response Header", "Content-Type")
        self.hashed_settings.ignore("Response Header", "Content-Length")
        
        self.stored_reflection_settings.ignore("Request Header", "Accept")
        self.stored_reflection_settings.ignore("Request Header", "Accept-Charset")
        self.stored_reflection_settings.ignore("Request Header", "Accept-Language")
        self.stored_reflection_settings.ignore("Request Header", "Accept-Encoding")
        self.stored_reflection_settings.ignore("Request Header", "Referer")
        self.stored_reflection_settings.ignore("Request Header", "User-Agent")
        self.stored_reflection_settings.ignore("Request Header", "Proxy-Connection")
        self.stored_reflection_settings.ignore("Request Header", "Host")
        self.stored_reflection_settings.ignore("Request Header", "Content-Length")
        self.stored_reflection_settings.ignore("Request Header", "Content-Type")
        
        self.stored_reflection_settings.ignore("Response Header", "If-None-Match")
        self.stored_reflection_settings.ignore("Response Header", "ETag")
        self.stored_reflection_settings.ignore("Response Header", "Date")
        self.stored_reflection_settings.ignore("Response Header", "Server")
        self.stored_reflection_settings.ignore("Response Header", "X-Powered-By")
        self.stored_reflection_settings.ignore("Response Header", "Cache-Control")
        self.stored_reflection_settings.ignore("Response Header", "Content-Type")
        self.stored_reflection_settings.ignore("Response Header", "Content-Length")
        self.stored_reflection_settings.ignore("Response Header", "")
        self.stored_reflection_settings.ignore("Form Field", "")

class SectionSetting:
    def __init__(self, hawas):
        self.black_list = {}
        self.white_list = {}
        
    def ignore(self, section, parameter_name):
        if not self.black_list.has_key(section):
            self.black_list[section] = []
        if self.black_list[section].count(parameter_name) == 0:
            self.black_list[section].append(parameter_name)
    
    def is_ignored(self, param):
        black_list_match = False
        for section in param.sections:
            if self.black_list.has_key(section):
                if self.black_list[section].count(param.name) > 0 or self.black_list[section].count("") > 0:
                    black_list_match = True
                else:
                    return False
            else:
                return False
        return black_list_match
    
    def is_value_ignored(self, value):
        if self.black_list.has_key(value.section):
            if self.black_list[value.section].count(value.parameter_name) > 0 or self.black_list[value.section].count("") > 0:
                return True
        return False

    def is_section_name_ignored(self, section, name):
        if self.black_list.has_key(section):
            if self.black_list[section].count(name) > 0 or self.black_list[section].count("") > 0:
                return True
        return False
