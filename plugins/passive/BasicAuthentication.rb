#Author: Manish Saindane
#License: MIT License - http://www.opensource.org/licenses/mit-license

include IronWASP

class BasicAuthentication < PassivePlugin
    
    def GetInstance()
    	p = BasicAuthentication.new
			p.name = "Basic Auth Check"
			p.version = "0.4"
			p.description = "This plugin checks for the use of Basic Authentication over insecure channels."
			#p.calling_state = PluginCallingState.before_interception
			p.works_on = PluginWorksOn.response
			return p
    end
    
    def Check(ironsess, results, report_all)
        if ironsess.Response.headers.has('WWW-Authenticate') and !ironsess.Request.ssl
            auth_method = ironsess.Response.headers.get('WWW-Authenticate')
            report_basic_auth(ironsess, 'WWW-Authenticate: ' + auth_method, results, report_all) if auth_method =~ /basic/i
        end
    end
    
    def report_basic_auth(ironsess, auth_method, results, report_all)
        signature = "high|basic authentication"
        if report_all or is_signature_unique(ironsess.Request.base_url, FindingType.vulnerability, signature)
	        plugin_result = Finding.new(ironsess.Request.base_url)
	        plugin_result.title = "Insecure Basic Authentication used"
	        plugin_result.summary = "The server uses Basic Authentication over insecure channel. Basic Authentication encodes the credentials using Base64 which can be easily decoded if captured over insecure channel."
	        plugin_result.triggers.add('', '',ironsess.Request, auth_method, 'The value of the WWW-Authenticate header from the server indicates support for Basic Authentication', ironsess.Response)
	        plugin_result.type = FindingType.vulnerability
	        plugin_result.confidence = FindingConfidence.high
	        plugin_result.severity = FindingSeverity.high
	        plugin_result.signature = signature
	        results.add(plugin_result)
        end
    end
end

p = BasicAuthentication.new
PassivePlugin.add(p.get_instance)