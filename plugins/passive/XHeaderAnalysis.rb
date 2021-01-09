#Author: Manish Saindane
#License: MIT License - http://www.opensource.org/licenses/mit-license


include IronWASP

class XHeaderAnalysis < PassivePlugin

    def GetInstance
        p = XHeaderAnalysis.new
        p.name = "X Header Analysis"
        p.version = "0.3"
        p.description = "Plugin used to analyse most of the X headers found in server responses"
        p.works_on = PluginWorksOn.response
        return p
    end

    def Check(sess, results, report_all)
    	@report_all = report_all
    	res = sess.response
    	technology_used(sess, results) if res.headers.has("x-powered-by")
        xss_protection_check(sess, results) if res.headers.has("x-xss-protection")
        xframe_options_check(sess, results) if res.headers.has("x-frame-options")
        x_content_type_options_check(sess, results) if res.headers.has("x-content-type-options")
    end

    def technology_used(sess, results)
    	tech_used = sess.response.headers.get("x-powered-by").strip
    	report_technology_used(sess, results, tech_used) unless tech_used.empty?
    end

    def xss_protection_check(sess, results)
        xss_protection = sess.response.headers.get("x-xss-protection").strip
        report_xss_protection(sess, results, xss_protection) unless xss_protection.empty?
    end

    def xframe_options_check(sess, results)
        xframe_value = sess.response.headers.get("x-frame-options").strip
        report_xframe_options(sess, results, xframe_value) unless xframe_value.empty?
    end

    def x_content_type_options_check(sess, results)
        value = sess.response.headers.get("x-content-type-options").strip
        report_x_content_type_options(sess, results, value) unless value.empty? or value !~ /nosniff/i
    end

    def report_technology_used(sess, results, tech_used)
    	signature = "technology|#{tech_used}"
    	if @report_all or is_signature_unique(sess.request.base_url, FindingType.information, signature)
            plugin_result = Finding.new(sess.request.base_url)
            plugin_result.title = "Technologies identified on Server"
            plugin_result.summary = "The server makes use of the following technologies:<i<br>> - #{tech_used}"
            plugin_result.triggers.add("",sess.request, tech_used, sess.response)
            plugin_result.signature = signature
            plugin_result.type = FindingType.information
            plugin_result.confidence = FindingConfidence.high
            plugin_result.severity = FindingSeverity.low
            results.add(plugin_result)
    	end
    end

    def report_xss_protection(sess, results, xss_protection)
        signature = "xss protection|#{xss_protection}"
        xss_protection.include?("0") ? vulnerable = true : vulnerable = false

        if @report_all or is_signature_unique(sess.request.base_url, FindingType.information, signature) or is_signature_unique(sess.request.base_url, FindingType.vulnerability, signature)
            plugin_result = Finding.new(sess.request.base_url)

            if vulnerable
                plugin_result.title = "XSS Filter disabled"
                plugin_result.summary = "The application appears to intentionally disable IE's cross-site "+
                                        "scripting filter.<i<br>> The reason for disabling this feature is usually to support sites that depend on the reflection behavior that Internet Explorer is looking for. However, this feature should only be disabled with the recognition that it will disable defense-in-depth protection for Cross-Site Scripting attacks in Internet Explorer. Best practices should be put in place to eliminate Cross-Site Scripting at the server regardless of if the XSS Filter is enabled or explicitly disabled at the client"
                plugin_result.triggers.add("",sess.request, "X-XSS-Protection: " + xss_protection, sess.response)
                plugin_result.signature = signature
                plugin_result.type = FindingType.vulnerability
                plugin_result.confidence = FindingConfidence.high
                plugin_result.severity = FindingSeverity.low
            else
                plugin_result.title = "XSS Protection in use"
                plugin_result.summary = "The application apprears to have enabled XSS protection via the X-XSS-Protection header."
                plugin_result.triggers.add("",sess.request, "X-XSS-Protection: " + xss_protection, sess.response)
                plugin_result.signature = signature
                plugin_result.type = FindingType.information
                plugin_result.confidence = FindingConfidence.high
                plugin_result.severity = FindingSeverity.low
            end

            results.add(plugin_result)
        end
    end

    def report_xframe_options(sess, results, xframe_value)
        signature = "xframe_options|#{xframe_value}"

        if @report_all or is_signature_unique(sess.request.base_url, FindingType.information, signature)
            plugin_result = Finding.new(sess.request.base_url)
            plugin_result.title = "ClickJacking Protection in use"
            plugin_result.summary = "The application appears to have enabled clickjacking protection via the X-Frame-Options header."
            plugin_result.triggers.add("",sess.request, "X-Frame-Options: " + xframe_value, sess.response)
            plugin_result.signature = signature
            plugin_result.type = FindingType.information
            plugin_result.confidence = FindingConfidence.high
            plugin_result.severity = FindingSeverity.low
            results.add(plugin_result)
        end
    end

    def report_x_content_type_options(sess, results, value)
        signature = "x_content_type_options|#{value}"

        if @report_all or is_signature_unique(sess.request.base_url, FindingType.information, signature)
            plugin_result = Finding.new(sess.request.base_url)
            plugin_result.title = "Mime Sniffing Protection in use"
            plugin_result.summary = "The application appears to have enabled MIME-sniffing pervention via the MIME-sniffing via the X-Content-Type-Options header."+
                                    "This header prevents Internet Explorer from MIME-sniffing a response away from the declared content-type."
            plugin_result.triggers.add("",sess.request, "X-Content-Type-Options: " + value, sess.response)
            plugin_result.signature = signature
            plugin_result.type = FindingType.information
            plugin_result.confidence = FindingConfidence.high
            plugin_result.severity = FindingSeverity.low
            results.add(plugin_result)
        end
    end
end

p = XHeaderAnalysis.new
PassivePlugin.add(p.get_instance)