from IronWASP import *
from IronSAPCore import start

class IronSAP(Module):
	
	#Override the GetInstance method of the base class to return a new instance with details
	def GetInstance(self):
		m = IronSAP()
		m.Name = "IronSAP"
		return m
	
	def StartModule(self):
		self.start_ui()
		
	def start_ui(self):
		self.thread_id = 0

		ui = ModUi()
		ui.Size = ModUiTools.GetSizeDefinition(800,600)
		ui.Text =  Tools.Base64Decode('SXJvblNBUCAtICBTQVAgU2VjdXJpdHkgU2Nhbm5lcg==')
		ui.Icon = ModUiTools.GetIconDefinition('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')
		verbose_output_cb = ModCheckBox()
		verbose_output_cb.Name = 'verbose_output_cb'
		verbose_output_cb.Size = ModUiTools.GetSizeDefinition(153,24)
		verbose_output_cb.Location = ModUiTools.GetLocationDefinition(155,58)
		verbose_output_cb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		verbose_output_cb.Dock = ModUiTools.GetDockStyleDefinition('None')
		verbose_output_cb.Enabled = True
		verbose_output_cb.BackColor = ModUiTools.GetColorDefinition(-986896)
		verbose_output_cb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		verbose_output_cb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		verbose_output_cb.Text =  Tools.Base64Decode('UHJvdmlkZSBWZXJib3NlIFJlc3VsdHM=')
		verbose_output_cb.Checked = False
		ui.Controls.Add(verbose_output_cb)
		ui.ModControls['verbose_output_cb'] = verbose_output_cb
		perform_attack_cb = ModCheckBox()
		perform_attack_cb.Name = 'perform_attack_cb'
		perform_attack_cb.Size = ModUiTools.GetSizeDefinition(104,24)
		perform_attack_cb.Location = ModUiTools.GetLocationDefinition(17,58)
		perform_attack_cb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		perform_attack_cb.Dock = ModUiTools.GetDockStyleDefinition('None')
		perform_attack_cb.Enabled = True
		perform_attack_cb.BackColor = ModUiTools.GetColorDefinition(-986896)
		perform_attack_cb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		perform_attack_cb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		perform_attack_cb.Text =  Tools.Base64Decode('UGVyZm9ybSBBdHRhY2tz')
		perform_attack_cb.Checked = False
		ui.Controls.Add(perform_attack_cb)
		ui.ModControls['perform_attack_cb'] = perform_attack_cb
		mod_tab_control_2 = ModTabControl()
		mod_tab_control_2.Name = 'mod_tab_control_2'
		mod_tab_control_2.Size = ModUiTools.GetSizeDefinition(780,471)
		mod_tab_control_2.Location = ModUiTools.GetLocationDefinition(2,88)
		mod_tab_control_2.Anchor = ModUiTools.GetAnchorStyleDefinition(True,True,True,True)
		mod_tab_control_2.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_tab_control_2.Enabled = True
		mod_tab_control_2.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_tab_control_2.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_tab_control_2.TabPages.Add('tab_page_2', '    Combined Results    ')
		combined_out_tb = ModTextBox()
		combined_out_tb.Name = 'combined_out_tb'
		combined_out_tb.Size = ModUiTools.GetSizeDefinition(772,445)
		combined_out_tb.Location = ModUiTools.GetLocationDefinition(0,0)
		combined_out_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		combined_out_tb.Dock = ModUiTools.GetDockStyleDefinition('Fill')
		combined_out_tb.Enabled = True
		combined_out_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		combined_out_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		combined_out_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		combined_out_tb.ReadOnly = True
		combined_out_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Both')
		combined_out_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		combined_out_tb.Multiline = True
		combined_out_tb.WordWrap = True
		combined_out_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		mod_tab_control_2.TabPages['tab_page_2'].Controls.Add(combined_out_tb)
		ui.ModControls['combined_out_tb'] = combined_out_tb
		mod_tab_control_2.TabPages.Add('tab_page_4', '    FingerPrint Results    ')
		fingerprint_out_tb = ModTextBox()
		fingerprint_out_tb.Name = 'fingerprint_out_tb'
		fingerprint_out_tb.Size = ModUiTools.GetSizeDefinition(772,445)
		fingerprint_out_tb.Location = ModUiTools.GetLocationDefinition(0,0)
		fingerprint_out_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		fingerprint_out_tb.Dock = ModUiTools.GetDockStyleDefinition('Fill')
		fingerprint_out_tb.Enabled = True
		fingerprint_out_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		fingerprint_out_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		fingerprint_out_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		fingerprint_out_tb.ReadOnly = True
		fingerprint_out_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Both')
		fingerprint_out_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		fingerprint_out_tb.Multiline = True
		fingerprint_out_tb.WordWrap = True
		fingerprint_out_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		mod_tab_control_2.TabPages['tab_page_4'].Controls.Add(fingerprint_out_tb)
		ui.ModControls['fingerprint_out_tb'] = fingerprint_out_tb
		mod_tab_control_2.TabPages.Add('tab_page_5', '    HTTP Analyser Results    ')
		http_analyzer_out_tb = ModTextBox()
		http_analyzer_out_tb.Name = 'http_analyzer_out_tb'
		http_analyzer_out_tb.Size = ModUiTools.GetSizeDefinition(772,445)
		http_analyzer_out_tb.Location = ModUiTools.GetLocationDefinition(0,0)
		http_analyzer_out_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		http_analyzer_out_tb.Dock = ModUiTools.GetDockStyleDefinition('Fill')
		http_analyzer_out_tb.Enabled = True
		http_analyzer_out_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		http_analyzer_out_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		http_analyzer_out_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		http_analyzer_out_tb.ReadOnly = True
		http_analyzer_out_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Both')
		http_analyzer_out_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		http_analyzer_out_tb.Multiline = True
		http_analyzer_out_tb.WordWrap = True
		http_analyzer_out_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		mod_tab_control_2.TabPages['tab_page_5'].Controls.Add(http_analyzer_out_tb)
		ui.ModControls['http_analyzer_out_tb'] = http_analyzer_out_tb
		mod_tab_control_2.TabPages.Add('tab_page_6', '    Web Services Results    ')
		web_services_out_tb = ModTextBox()
		web_services_out_tb.Name = 'web_services_out_tb'
		web_services_out_tb.Size = ModUiTools.GetSizeDefinition(772,445)
		web_services_out_tb.Location = ModUiTools.GetLocationDefinition(0,0)
		web_services_out_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		web_services_out_tb.Dock = ModUiTools.GetDockStyleDefinition('Fill')
		web_services_out_tb.Enabled = True
		web_services_out_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		web_services_out_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		web_services_out_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		web_services_out_tb.ReadOnly = True
		web_services_out_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Both')
		web_services_out_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		web_services_out_tb.Multiline = True
		web_services_out_tb.WordWrap = True
		web_services_out_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		mod_tab_control_2.TabPages['tab_page_6'].Controls.Add(web_services_out_tb)
		ui.ModControls['web_services_out_tb'] = web_services_out_tb
		mod_tab_control_2.TabPages.Add('tab_page_7', '    RFC    ')
		banner_rfc = ModLabel()
		banner_rfc.Name = 'banner_rfc'
		banner_rfc.Size = ModUiTools.GetSizeDefinition(363,44)
		banner_rfc.Location = ModUiTools.GetLocationDefinition(179,182)
		banner_rfc.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		banner_rfc.Dock = ModUiTools.GetDockStyleDefinition('None')
		banner_rfc.Enabled = True
		banner_rfc.BackColor = ModUiTools.GetColorDefinition(16777215)
		banner_rfc.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		banner_rfc.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		banner_rfc.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',15.75,True,True,False,False)
		banner_rfc.Text =  Tools.Base64Decode('Q29tbWluZyBVcCBOZXh0')
		mod_tab_control_2.TabPages['tab_page_7'].Controls.Add(banner_rfc)
		ui.ModControls['banner_rfc'] = banner_rfc
		ui.Controls.Add(mod_tab_control_2)
		ui.ModControls['mod_tab_control_2'] = mod_tab_control_2
		start_btn = ModButton()
		start_btn.Name = 'start_btn'
		start_btn.Size = ModUiTools.GetSizeDefinition(92,23)
		start_btn.Location = ModUiTools.GetLocationDefinition(504,27)
		start_btn.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		start_btn.Dock = ModUiTools.GetDockStyleDefinition('None')
		start_btn.Enabled = True
		start_btn.BackColor = ModUiTools.GetColorDefinition(-986896)
		start_btn.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		start_btn.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		start_btn.Text =  Tools.Base64Decode('U3RhcnQ=')
		start_btn.Click += lambda s,e: self.start()
		ui.Controls.Add(start_btn)
		ui.ModControls['start_btn'] = start_btn
		url_tb = ModTextBox()
		url_tb.Name = 'url_tb'
		url_tb.Size = ModUiTools.GetSizeDefinition(330,20)
		url_tb.Location = ModUiTools.GetLocationDefinition(155,30)
		url_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		url_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		url_tb.Enabled = True
		url_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		url_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		url_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		url_tb.ReadOnly = False
		url_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('None')
		url_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		url_tb.Multiline = False
		url_tb.WordWrap = True
		url_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		ui.Controls.Add(url_tb)
		ui.ModControls['url_tb'] = url_tb
		mod_label_7 = ModLabel()
		mod_label_7.Name = 'mod_label_7'
		mod_label_7.Size = ModUiTools.GetSizeDefinition(150,23)
		mod_label_7.Location = ModUiTools.GetLocationDefinition(13,32)
		mod_label_7.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_7.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_7.Enabled = True
		mod_label_7.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_7.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_7.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_7.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_7.Text =  Tools.Base64Decode('RW50ZXIgdGFyZ2V0IElQL0hvc3RuYW1lOg==')
		ui.Controls.Add(mod_label_7)
		ui.ModControls['mod_label_7'] = mod_label_7
		mod_label_8 = ModLabel()
		mod_label_8.Name = 'mod_label_8'
		mod_label_8.Size = ModUiTools.GetSizeDefinition(104,23)
		mod_label_8.Location = ModUiTools.GetLocationDefinition(1114,20)
		mod_label_8.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_8.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_8.Enabled = True
		mod_label_8.BackColor = ModUiTools.GetColorDefinition(-16744448)
		mod_label_8.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_8.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_8.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',15.75,True,True,False,False)
		mod_label_8.Text =  Tools.Base64Decode('SXJvblNBUA==')
		ui.Controls.Add(mod_label_8)
		ui.ModControls['mod_label_8'] = mod_label_8
		ui.ShowUi()
		
		self.ui = ui
	
	def start(self):
		if self.ui.ModControls['start_btn'].Text == "Start":
			if self.ui.ModControls['perform_attack_cb'].Checked == True:
				self.perform_attack = True
			else:
				self.perform_attack = False
			if self.ui.ModControls['verbose_output_cb'].Checked == True:
				self.verbose = True
			else:
				self.verbose = False
			self.target = self.ui.ModControls['url_tb'].Text
			try:
				self.thread_id = IronThread.Run(start.begin, self)
				self.ui.ModControls['start_btn'].SetText("Stop")
			except Exception as e:
				self.ui.ModControls['combined_out_tb'].SetText("Error Scanning - {0}".format(e.message))
		else:
			IronThread.Stop(self.thread_id)
			self.ui.ModControls['combined_out_tb'].AddText('Scanning stopped.\r\n')
			self.ui.ModControls['start_btn'].SetText("Start")
			
	def stopper(self):
		#self.print_out("Stopping scan....",0)
		self.print_out("Scan stopped",0)
		self.ui.ModControls['start_btn'].SetText("Start")
		try:
			IronThread.Stop(self.thread_id)
		except:
			pass
	
	def print_out(self, data, place):
		self.ui.ModControls['combined_out_tb'].AddText("{0}\r\n".format(data))
		if place == 1:
			self.ui.ModControls['fingerprint_out_tb'].AddText("{0}\r\n".format(data))
		elif place == 2:
			self.ui.ModControls['http_analyzer_out_tb'].AddText("{0}\r\n".format(data))
		elif place == 3:
			self.ui.ModControls['web_services_out_tb'].AddText("{0}\r\n".format(data))

m = IronSAP()
Module.Add(m.GetInstance())
