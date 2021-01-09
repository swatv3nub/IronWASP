#Author: Manish Saindane
#License: MIT License - http://www.opensource.org/licenses/mit-license

include IronWASP

class DirListing < PassivePlugin

    def GetInstance
        p = DirListing.new
        p.name = "Directory Listing"
        p.version = "0.3"
        p.description = "Identifies directory listing issuses in the website being tested."
        p.works_on = PluginWorksOn.response
        return p
    end

    def Check(sess, results, report_all)
        res = sess.response
        matches_found = dir_listing_check(res)
        report_vuln(sess, results, matches_found, report_all) unless matches_found.empty?
    end

    def dir_listing_check(res)
        regexs = ['<title>Index of /',
        			'Parent Directory</a>',
        			'Directory Listing for',
        			'<TITLE>Folder Listing',
        			'<table summary="Directory Listing" ',
        			'- Browsing directory ',
        			'[To Parent Directory]']
        ret_arr = []

    		if res.is_html:
	    		regexs.each do |regex|
	        	escaped_regex = Regexp.escape(regex)
	        	match = /#{escaped_regex}/im.match(res.body_string)
	        	ret_arr = match.to_a unless match.nil?
	    		end
	    	end
        return ret_arr
    end

    def report_vuln(sess, results, matches_found, report_all)
    	req = sess.request
    	res = sess.response
      signature = "DirListing|#{req.url_path}"

        if report_all or is_signature_unique(sess.Request.base_url, FindingType.vulnerability, signature)
          plugin_result = Finding.new(req.base_url)
        	plugin_result.title = "Directory Listing at : #{req.url_path}"
        	plugin_result.summary = "A directory listing vulnerability was found at <i<hlo>>#{req.url_path}<i</hlo>><i<br>>"+
          "A directory listing provides an attacker with the complete index of all the resources located"+
          "inside of the directory. The specific risks and consequences vary depending"+
          "on which files are listed and accessible.<i<br>>"+
          "<i<cb>><i<b>>References:<i</b>><i</cb>><i<br>>CWE-548: Information Exposure Through Directory Listing"
          plugin_result.triggers.add("", "", req, matches_found.join('\r\n'), 'Text found in this response body indicates that there is Directory Listing on the server', res)
        	plugin_result.severity = FindingSeverity.medium
        	plugin_result.confidence = FindingConfidence.medium
        	plugin_result.signature = signature
        	results.add(plugin_result)
        end
    end
end

p = DirListing.new
PassivePlugin.add(p.get_instance)
