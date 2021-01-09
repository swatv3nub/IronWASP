#Author: Manish Saindane
#License: MIT License - http://www.opensource.org/licenses/mit-license
 
include IronWASP

class WebServerAnalysis < PassivePlugin

  def GetInstance()
  	p = WebServerAnalysis.new
		p.name = "Web Server Identification"
		p.version = "0.4"
		p.description = "This plugin analyzes the 'Server' header in the HTTP response and reports interesting information from it"
		#p.calling_state = PluginCallingState.before_interception
		p.works_on = PluginWorksOn.response
		return p
  end
  
  def Check(ironsess, results, report_all)
    @report_all = report_all
    banner=""
    if ironsess.Response.headers.has("Server")
      banner = ironsess.Response.headers.get("Server")
      if banner.length > 0
        report_server_name(ironsess, results, banner)
        check_version(ironsess, results, banner)
      end
    end
  end
  
  def report_server_name(ironsess, results, banner)
  	signature = "serverheader|#{banner}"
  	if @report_all or is_signature_unique(ironsess.Request.base_url, FindingType.information, signature)
	    plugin_result = Finding.new(ironsess.Request.base_url)
	    plugin_result.title = "Runs on #{banner}"
	    plugin_result.summary = "The Web Server returned this banner in its response headers - #{banner}"
	    plugin_result.triggers.add("",ironsess.Request,'Server:' + banner,ironsess.Response)
	    plugin_result.type = FindingType.information
	    plugin_result.severity = FindingSeverity.low
			plugin_result.confidence = FindingConfidence.high
	    plugin_result.signature = signature
	    results.add(plugin_result)
    end
  end
  
  def check_version(ironsess, results, banner)
    /(.+?)\/([\d\.\-]+)/.match(banner)
    if $2 != nil
      report_version_found(ironsess, results, banner, $2)
      check_if_version_old(ironsess, results, banner, $1, $2)
    end
  end
  
  def report_version_found(ironsess, results, banner, version)
    signature = "low|serverversion|#{banner}"
    if @report_all or is_signature_unique(ironsess.Request.base_url, FindingType.vulnerability, signature)
	    plugin_result = Finding.new(ironsess.Request.base_url)
	    plugin_result.title = "Server leaks version number"
	    plugin_result.summary = "The Web Server's banner contains the version number of the server - #{banner}. The version number found is #{version}"
	    plugin_result.triggers.add('','',ironsess.Request, 'Server:' + banner, "The Server header of this Response indicates the server version as #{version}",ironsess.Response)
	    plugin_result.type = FindingType.vulnerability
	    plugin_result.confidence = FindingConfidence.high
	    plugin_result.severity = FindingSeverity.low
	    plugin_result.signature = signature
	    results.add(plugin_result)
    end
  end
  
  def check_if_version_old(ironsess, results, banner, name, version)
    version_parts = version.split(".")
    if (name.casecmp "Apache") == 0
      if version_parts[0].to_i == 1
        title = "Deprecated version of Apache used (#{version})"
        summary = "The version of Apache server as per the banner is deprecated and is not supported anymore. (#{version})"
        report_vulnerable_version(ironsess, results, title, summary, banner, name, FindingSeverity.high, FindingConfidence.high)
      end
    elsif (name.casecmp "IIS") == 0
      if version_parts[0].to_i < 5
        title = "Deprecated version of IIS used (#{version})"
        summary = "The version of IIS server as per the banner is deprecated and is not supported anymore. (#{version})"
        report_vulnerable_version(ironsess, results, title, summary, banner, name, FindingSeverity.high, FindingConfidence.high)
      elsif version_parts[0].to_i == 5 && version_parts[1].to_i == 0
        title = "Vulnerable version of IIS used (#{version})"
        summary = "The version of IIS server as per the banner is outdated and suffers from multiple severe vulerabilities. (#{version})"
        report_vulnerable_version(ironsess, results, title, summary, banner, name, FindingSeverity.high, FindingConfidence.high)
      end
    end
  end
  
  def report_vulnerable_version(ironsess, results, title, summary, banner, name, severity, confidence)
    signature = "vulnerableversion|#{banner}|#{title}"
    if @report_all or is_signature_unique(ironsess.Request.base_url, FindingType.vulnerability, signature)
	    plugin_result = Finding.new(ironsess.Request.base_url)
	    plugin_result.title = title
	    plugin_result.summary = summary
	    plugin_result.triggers.add('', '', ironsess.Request, "Server: " + banner, 'The version number in the Server header of this response is a vulnerable version', ironsess.Response)
	    plugin_result.type = FindingType.vulnerability
	    plugin_result.confidence = confidence
	    plugin_result.severity = severity
	    plugin_result.signature = signature
	    results.add(plugin_result)
    end
  end
end

p = WebServerAnalysis.new
PassivePlugin.add(p.get_instance)
