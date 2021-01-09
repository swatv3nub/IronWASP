#Author: Manish Saindane
#License: MIT License - http://www.opensource.org/licenses/mit-license

include IronWASP

class CookieAnalysis < PassivePlugin

  def GetInstance()
  	p = CookieAnalysis.new
		p.name = "CookieAnalysis"
		p.version = "0.4"
		p.description = "This plugin analyses cookies set by server responses and reports cookies missing 'HTTPOnly' flag and if the response is over SSL then whether the 'secure' flag is set and also alerts the user if it may contain sensitive information."
		#p.calling_state = PluginCallingState.before_interception
		p.works_on = PluginWorksOn.response
		return p
  end
  
  def Check(ironsess, results, report_all)
    if ironsess.Response.Headers.has("Set-Cookie")
      cookie_jar = ironsess.Response.set_cookies
      cookie_jar.each do |cookie|
        check_httponly(ironsess, results, cookie, report_all)
        check_secure(ironsess, results, cookie, report_all) if ironsess.Request.ssl
        check_sensitive_info(ironsess, results, cookie, report_all)
      end
    end
  end
  
  def check_httponly(ironsess, results, cookie, report_all)
    flag = cookie.http_only
    if !flag
        signature = "cookie|#{cookie.name}|httponly"
        if report_all or is_signature_unique(ironsess.Request.base_url, FindingType.vulnerability, signature)
	        plugin_result = Finding.new(ironsess.Request.base_url)
	        plugin_result.title = "Cookie #{cookie.name} missing the HttpOnly flag"
	        plugin_result.summary = "The HttpOnly flag was missing on the cookie: #{cookie.name}. This may allow an attacker to get the cookie information using XSS attacks."
	        plugin_result.triggers.add("","",ironsess.Request, 'Set-Cookie:' + cookie.full_string, 'The value of the cookie is not protected by HttpOnly flag and hence becomes accessible from JavaScript',ironsess.Response)
	        plugin_result.signature = signature
	        plugin_result.type = FindingType.vulnerability
	        plugin_result.confidence = FindingConfidence.high
	        plugin_result.severity = FindingSeverity.medium
	        results.add(plugin_result)
       	end
    end
  end
  
  def check_secure(ironsess, results, cookie, report_all)
    flag = cookie.secure
    if !flag
    	signature = "cookie|#{cookie.name}|secure"
    	if report_all or is_signature_unique(ironsess.Request.base_url, FindingType.vulnerability, signature)
        plugin_result = Finding.new(ironsess.Request.base_url)
        plugin_result.title = "Cookie #{cookie.name} missing the Secure flag"
        plugin_result.summary = "The Secure flag was missing on the cookie: #{cookie.name}. This may allow the cookie to be transferred over an insecure channel."
        plugin_result.triggers.add("","",ironsess.Request, 'Set-Cookie:' + cookie.full_string,'The value of the cookie is not protected by Secure flag and hence becomes accessible over HTTP', ironsess.Response)
        plugin_result.signature = signature
        plugin_result.type = FindingType.vulnerability
        plugin_result.severity = FindingSeverity.medium
        plugin_result.confidence = FindingConfidence.high
        results.add(plugin_result)
    	end
    end
  end
  
  def check_sensitive_info(ironsess, results, cookie, report_all)
    r = Regexp.new('user|pass|uid|pwd|admin|attempt|retr|login|auth|secure|limit', Regexp::IGNORECASE)
    if r =~ cookie.value or r =~ cookie.name
      signature = "cookie|#{cookie.name}|sensitive info"
      if report_all or is_signature_unique(ironsess.Request.base_url, FindingType.test_lead, signature)
        plugin_result = Finding.new(ironsess.Request.base_url)
        plugin_result.title = "Cookie #{cookie.name} may contain sensitive information"
        plugin_result.summary = "The cookie: #{cookie.name} might contain sensitive information which could be easily accessed or modified to exploit the web application."
        plugin_result.triggers.add("","",ironsess.Request, 'Set-Cookie:' + cookie.full_string, 'The cookie name or value indicates that it could hold important information', ironsess.Response)
        plugin_result.signature = signature
        plugin_result.type = FindingType.test_lead
        plugin_result.severity = FindingSeverity.medium
        plugin_result.confidence = FindingConfidence.low
        results.add(plugin_result)
      end
    end
  end
end

p = CookieAnalysis.new
PassivePlugin.add(p.get_instance)
