from IronWASP import *
from HAWASCore import LogReader
from HAWASCore import Structures
from HAWASCore import HawasConfig

class HAWAS(Module):
	
	#Override the GetInstance method of the base class to return a new instance with details
	def GetInstance(self):
		m = HAWAS()
		m.Name = "HAWAS"
		return m
	
	def StartModule(self):
		self.start_ui()
	
	def start_ui(self):
		self.thread_id = 0
		ui = ModUi()
		ui.Size = ModUiTools.GetSizeDefinition(900,600)
		ui.Text =  Tools.Base64Decode('SEFXQVMgLSBIeWJyaWQgQW5hbHl6ZXIgZm9yIFdlYiBBcHBsaWNhdGlvbiBTZWN1cml0eQ==')
		ui.Icon = ModUiTools.GetIconDefinition('AAABAAIAEBAAAAAAIABoBAAAJgAAACAgAAAAACAAqBAAAI4EAAAoAAAAEAAAACAAAAABACAAAAAAAEAEAAAAAAAAAAAAAAAAAAAAAAAA//////////////////////n5+f/IyMj/gYGB/2hoaP9oaGj/fX19/8DAwP/29vb//////////////////////////////////////9DQ0P9HR0f/VFRU/5ycnP/ExMT/xMTE/6Wlpf9aWlr/Pz8//8DAwP///////////////////////////7Gxsf8QEBD/n5+f//z8/P///////////////////////f39/8bGxv8JCQn/np6e/////////////////9DQ0P8xMTH/ERER/5aWlv/////////////////////////////////MzMz/BQUF/zIyMv+9vb3///////n5+f9HR0f/ubm5/ysrK/96enr/////////////////////////////////l5eX/yQkJP/IyMj/Pz8///Ly8v/Jycn/VVVV//r6+v9CQkL/VlZW/////////////////////////////////25ubv9ERET//Pz8/2VlZf+wsLD/hISE/5ycnP//////VlZW/zU1Nf/8/Pz//Pz8//z8/P/8/Pz//Pz8//z8/P88PDz/ampq//////+4uLj/bW1t/2hoaP/ExMT//////35+fv8GBgb/Pz8//z8/P/8/Pz//Pz8//z8/P/8/Pz//BgYG/5ubm///////zs7O/19fX/9oaGj/xMTE//////+fn5//AQEB/xUVFf8XFxf/FxcX/xcXF/8XFxf/ExMT/wQEBP+8vLz//////8/Pz/9hYWH/f39//6SkpP//////tbW1/wgICP/Dw8P/+vr6//r6+v/6+vr/+vr6/6urq/8SEhL/4eHh//////++vr7/aGho/8LCwv9XV1f//f39/9XV1f8NDQ3/qqqq//////////////////////+EhIT/Gxsb//z8/P/+/v7/cHBw/6mpqf/29vb/Pj4+/9LS0v/t7e3/FBQU/5CQkP/////////////////+/v7/UVFR/01NTf//////5OTk/zo6Ov/v7+///////8PDw/89PT3/6enp/xwcHP9mZmb/////////////////9fX1/zExMf93d3f/8vLy/0xMTP+qqqr/////////////////n5+f/0FBQf8pKSn/RkZG//39/f///////////+Li4v8RERH/iYmJ/0xMTP+Wlpb//v7+///////////////////////AwMD/MjIy/yQkJP+3t7f/zMzM/8zMzP+hoaH/AAAA/y0tLf+qqqr//v7+//////////////////////////////////Ly8v+ysrL/bW1t/19fX/9eXl7/a2tr/6mpqf/v7+///////////////////////wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8oAAAAIAAAAEAAAAABACAAAAAAAIAQAAAAAAAAAAAAAAAAAAAAAAAA///////////////////////////////////////////////////////////09PT/4uLi/9XV1f/R0dH/0dHR/9HR0f/R0dH/0tLS/+Hh4f/x8fH//f39///////////////////////////////////////////////////////////////////////////////////////////////////////n5+f/rq6u/35+fv8+Pj7/Dw8P/wAAAP8AAAD/AAAA/wAAAP8FBQX/Ojo6/3Nzc/+goKD/3Nzc///////////////////////////////////////////////////////////////////////////////////////6+vr/oqKi/1dXV/8ODg7/ERER/z4+Pv9ra2v/iYmJ/4mJif+JiYn/iYmJ/3R0dP9OTk7/Gxsb/wQEBP9JSUn/kJCQ/+jo6P//////////////////////////////////////////////////////////////////////29vb/2xsbP8XFxf/DAwM/3Fxcf/AwMD/19fX/+/v7///////////////////////9PT0/+Dg4P/FxcX/g4OD/xYWFv8ODg7/UlJS/8nJyf///////////////////////////////////////////////////////v7+/8zMzP88PDz/BQUF/zIyMv/i4uL/9fX1///////////////////////////////////////////////////////39/f/5eXl/2dnZ/8EBAT/Gxsb/7q6uv/9/f3////////////////////////////////////////////MzMz/Ly8v/wAAAP8AAAD/bW1t//v7+//////////////////////////////////////////////////////////////////+/v7/y8vL/wcHB/8AAAD/CAgI/7i4uP//////////////////////////////////////29vb/z09Pf8LCwv/EBAQ/wAAAP9ISEj/+vr6//////////////////////////////////////////////////////////////////7+/v+2trb/AAAA/wAAAP8QEBD/HBwc/8jIyP////////////////////////////r6+v9sbGz/Dg4O/21tbf80NDT/AAAA/x8fH//39/f//////////////////////////////////////////////////////////////////Pz8/4GBgf8AAAD/FhYW/4uLi/8QEBD/TU1N/+Dg4P//////////////////////oqKi/xcXF/9DQ0P/19fX/1FRUf8AAAD/CQkJ//f39//////////////////////////////////////////////////////////////////6+vr/TU1N/wAAAP82Njb/1tbW/3t7e/8JCQn/h4eH/////////////////+fn5/9YWFj/DAwM/+Li4v/n5+f/XFxc/wAAAP8AAAD/5+fn//////////////////////////////////////////////////////////////////j4+P8cHBz/AAAA/1paWv/m5ub/6urq/zY2Nv80NDT/zMzM////////////srKy/xMTE/9xcXH/9fX1//j4+P+AgID/AAAA/wAAAP/IyMj/////////////////////////////////////////////////////////////////8vLy/wEBAf8AAAD/g4OD//n5+f/6+vr/m5ub/wMDA/+SkpL/+vr6//T09P9+fn7/ERER/8DAwP///////Pz8/4mJif8AAAD/AAAA/5GRkf/////////////////////////////////////////////////////////////////Hx8f/AAAA/wAAAP+NjY3//v7+///////MzMz/KCgo/09PT//n5+f/4uLi/z09Pf8+Pj7/19fX////////////j4+P/wAAAP8AAAD/cnJy/////////////////////////////////////////////////////////////////4+Pj/8AAAD/FRUV/6enp////////////+/v7/9ra2v/Dw8P/9XV1f/Y2Nj/Ghoa/2tra//v7+////////////+urq7/Ghoa/wAAAP9hYWH/+vr6//r6+v/6+vr/+vr6//r6+v/6+vr/+vr6//r6+v/6+vr/+vr6//r6+v/6+vr/Y2Nj/wAAAP8sLCz/wcHB/////////////v7+/4iIiP8AAAD/z8/P/9HR0f8AAAD/iYmJ/////////////////8DAwP8qKir/AAAA/xgYGP9/f3//fn5+/35+fv9+fn7/fn5+/35+fv9+fn7/fn5+/35+fv9+fn7/fn5+/39/f/8YGBj/AAAA/0NDQ//c3Nz/////////////////mZmZ/wwMDP+tra3/0dHR/wAAAP+JiYn/////////////////09PT/zs7O/8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/WVlZ//T09P////////////////+hoaH/ExMT/7Gxsf/R0dH/AAAA/4mJif/////////////////j4+P/SUlJ/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP9kZGT//////////////////////6Ojo/8UFBT/sbGx/9HR0f8AAAD/iYmJ//////////////////b29v9aWlr/AAAA/wQEBP8iIiL/MTEx/y8vL/8vLy//Ly8v/y8vL/8vLy//Ly8v/y8vL/8vLy//MjIy/xsbG/8CAgL/Dw8P/4+Pj///////////////////////m5ub/w4ODv+vr6//1dXV/w8PD/91dXX/9PT0/////////////v7+/2VlZf8BAQH/EBAQ/5ubm//19fX/9fX1//X19f/19fX/9fX1//X19f/19fX/9fX1//X19f/09PT/cnJy/wcHB/8aGhr/srKy//////////////////////+Kior/AAAA/8HBwf/g4OD/Nzc3/0lJSf/d3d3/////////////////dHR0/wYGBv8JCQn/fX19//////////////////////////////////////////////////f39/9PT0//AAAA/yYmJv/V1dX/////////////////9/f3/3p6ev8LCwv/1NTU//Hx8f9zc3P/EhIS/8DAwP////////////////+fn5//FBQU/wQEBP9lZWX/+/v7////////////////////////////////////////////4+Pj/0JCQv8AAAD/MTEx//X19f/////////////////V1dX/OTk5/z4+Pv/i4uL//f39/6ampv8MDAz/gICA//f39////////////7e3t/8cHBz/AAAA/1BQUP/4+Pj////////////////////////////////////////////BwcH/Kioq/wAAAP89PT3//f39/////////////f39/62trf8HBwf/i4uL//j4+P//////3Nzc/0lJSf8PDw//5OTk////////////yMjI/yIiIv8AAAD/SkpK/+/v7////////////////////////////////////////v7+/6SkpP8XFxf/AgIC/4GBgf/////////////////s7Oz/PT09/ygoKP/CwsL/////////////////kpKS/w4ODv9ra2v/+fn5///////u7u7/Li4u/wAAAP81NTX/0dHR///////////////////////////////////////8/Pz/hYWF/wQEBP8DAwP/rq6u/////////////////6enp/8FBQX/f39///7+/v/////////////////w8PD/V1dX/w4ODv+pqan///////n5+f81NTX/AAAA/yIiIv+1tbX///////////////////////////////////////b29v91dXX/AAAA/wUFBf/T09P////////////Ly8v/ExMT/zExMf/Ly8v////////////////////////////Jycn/HBwc/yAgIP+wsLD//////zw8PP8AAAD/GRkZ/6enp///////////////////////////////////////4eHh/1FRUf8AAAD/CgoK//n5+f//////zMzM/0JCQv8QEBD/ra2t//////////////////////////////////////+6urr/CgoK/yEhIf+3t7f/b29v/wEBAf8KCgr/kJCQ//7+/v/////////////////////////////////Ly8v/LCws/wAAAP8TExP//////8vLy/9CQkL/BgYG/6urq//7+/v///////////////////////////////////////39/f+6urr/Gxsb/xISEv8yMjL/AQEB/wAAAP99fX3/+/v7/////////////////////////////v7+/7+/v/8aGhr/AAAA/2BgYP+ysrL/ExMT/xAQEP+rq6v/+/v7///////////////////////////////////////////////////////IyMj/UVFR/woKCv8AAAD/AAAA/29vb//u7u7//v7+///////////////////////8/Pz/pKSk/wAAAP8AAAD/CAgI/wUFBf8xMTH/ra2t//v7+//////////////////////////////////////////////////////////////////n5+f/ioqK/zQ0NP8AAAD/ICAg/2hoaP+IiIj/mpqa/5mZmf+ZmZn/nJyc/4mJif9cXFz/AAAA/wAAAP8oKCj/gICA/8vLy///////////////////////////////////////////////////////////////////////////////////////zMzM/5OTk/9RUVH/Dg4O/wAAAP8NDQ3/DAwM/wwMDP8ODg7/AAAA/wsLC/8/Pz//i4uL/8LCwv/+/v7/////////////////////////////////////////////////////////////////////////////////////////////////+vr6/+jo6P/V1dX/z8/P/7CwsP+ysrL/srKy/62trf/Pz8//1NTU/+Li4v/4+Pj//////////////////////////////////////////////////////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
		mod_label_1 = ModLabel()
		mod_label_1.Name = 'mod_label_1'
		mod_label_1.Size = ModUiTools.GetSizeDefinition(353,23)
		mod_label_1.Location = ModUiTools.GetLocationDefinition(165,14)
		mod_label_1.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_1.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_1.Enabled = True
		mod_label_1.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_1.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_1.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_1.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_1.Text =  Tools.Base64Decode('Q2xpY2sgb24gdGhlIFN0YXJ0IEFuYWx5c2lzIGJ1dHRvbiB0byBzdGFydCBhbiBhbmFseXNpcyBvZiB0aGUgUHJveHkgbG9ncw==')
		ui.Controls.Add(mod_label_1)
		ui.ModControls['mod_label_1'] = mod_label_1
		show_results_btn = ModButton()
		show_results_btn.Name = 'show_results_btn'
		show_results_btn.Size = ModUiTools.GetSizeDefinition(135,23)
		show_results_btn.Location = ModUiTools.GetLocationDefinition(12,45)
		show_results_btn.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		show_results_btn.Dock = ModUiTools.GetDockStyleDefinition('None')
		show_results_btn.Enabled = True
		show_results_btn.BackColor = ModUiTools.GetColorDefinition(-986896)
		show_results_btn.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		show_results_btn.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		show_results_btn.Text =  Tools.Base64Decode('U2hvdyBSZXN1bHRz')
		show_results_btn.Click += lambda s,e: self.show_results()
		ui.Controls.Add(show_results_btn)
		ui.ModControls['show_results_btn'] = show_results_btn
		status_lbl = ModLabel()
		status_lbl.Name = 'status_lbl'
		status_lbl.Size = ModUiTools.GetSizeDefinition(653,23)
		status_lbl.Location = ModUiTools.GetLocationDefinition(165,45)
		status_lbl.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		status_lbl.Dock = ModUiTools.GetDockStyleDefinition('None')
		status_lbl.Enabled = True
		status_lbl.BackColor = ModUiTools.GetColorDefinition(-986896)
		status_lbl.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		status_lbl.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		status_lbl.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		status_lbl.Text =  Tools.Base64Decode('ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg')
		ui.Controls.Add(status_lbl)
		ui.ModControls['status_lbl'] = status_lbl
		result_tabs = ModTabControl()
		result_tabs.Name = 'result_tabs'
		result_tabs.Size = ModUiTools.GetSizeDefinition(875,478)
		result_tabs.Location = ModUiTools.GetLocationDefinition(5,80)
		result_tabs.Anchor = ModUiTools.GetAnchorStyleDefinition(True,True,True,True)
		result_tabs.Dock = ModUiTools.GetDockStyleDefinition('None')
		result_tabs.Enabled = True
		result_tabs.BackColor = ModUiTools.GetColorDefinition(-986896)
		result_tabs.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		result_tabs.TabPages.Add('parameter_names_tab', '  Parameter Names and Values  ')
		pnv_selected_value_log_ids_tb = ModTextBox()
		pnv_selected_value_log_ids_tb.Name = 'pnv_selected_value_log_ids_tb'
		pnv_selected_value_log_ids_tb.Size = ModUiTools.GetSizeDefinition(313,55)
		pnv_selected_value_log_ids_tb.Location = ModUiTools.GetLocationDefinition(550,393)
		pnv_selected_value_log_ids_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		pnv_selected_value_log_ids_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		pnv_selected_value_log_ids_tb.Enabled = True
		pnv_selected_value_log_ids_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		pnv_selected_value_log_ids_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		pnv_selected_value_log_ids_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		pnv_selected_value_log_ids_tb.ReadOnly = True
		pnv_selected_value_log_ids_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		pnv_selected_value_log_ids_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		pnv_selected_value_log_ids_tb.Multiline = True
		pnv_selected_value_log_ids_tb.WordWrap = True
		pnv_selected_value_log_ids_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['parameter_names_tab'].Controls.Add(pnv_selected_value_log_ids_tb)
		ui.ModControls['pnv_selected_value_log_ids_tb'] = pnv_selected_value_log_ids_tb
		selected_value_log_ids_lbl = ModLabel()
		selected_value_log_ids_lbl.Name = 'selected_value_log_ids_lbl'
		selected_value_log_ids_lbl.Size = ModUiTools.GetSizeDefinition(303,16)
		selected_value_log_ids_lbl.Location = ModUiTools.GetLocationDefinition(548,374)
		selected_value_log_ids_lbl.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		selected_value_log_ids_lbl.Dock = ModUiTools.GetDockStyleDefinition('None')
		selected_value_log_ids_lbl.Enabled = True
		selected_value_log_ids_lbl.BackColor = ModUiTools.GetColorDefinition(-986896)
		selected_value_log_ids_lbl.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		selected_value_log_ids_lbl.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		selected_value_log_ids_lbl.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		selected_value_log_ids_lbl.Text =  Tools.Base64Decode('UHJveHkgTG9nIElEcyBvZiBSZXF1ZXN0cy9SZXNwb25zZXMgY29udGFpbmluZyB0aGlzIHZhbHVlOg==')
		result_tabs.TabPages['parameter_names_tab'].Controls.Add(selected_value_log_ids_lbl)
		ui.ModControls['selected_value_log_ids_lbl'] = selected_value_log_ids_lbl
		select_value_lbl = ModLabel()
		select_value_lbl.Name = 'select_value_lbl'
		select_value_lbl.Size = ModUiTools.GetSizeDefinition(100,15)
		select_value_lbl.Location = ModUiTools.GetLocationDefinition(548,268)
		select_value_lbl.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		select_value_lbl.Dock = ModUiTools.GetDockStyleDefinition('None')
		select_value_lbl.Enabled = True
		select_value_lbl.BackColor = ModUiTools.GetColorDefinition(-986896)
		select_value_lbl.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		select_value_lbl.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		select_value_lbl.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		select_value_lbl.Text =  Tools.Base64Decode('U2VsZWN0ZWQgVmFsdWU6')
		result_tabs.TabPages['parameter_names_tab'].Controls.Add(select_value_lbl)
		ui.ModControls['select_value_lbl'] = select_value_lbl
		pnv_selected_value_tb = ModTextBox()
		pnv_selected_value_tb.Name = 'pnv_selected_value_tb'
		pnv_selected_value_tb.Size = ModUiTools.GetSizeDefinition(314,88)
		pnv_selected_value_tb.Location = ModUiTools.GetLocationDefinition(550,283)
		pnv_selected_value_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		pnv_selected_value_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		pnv_selected_value_tb.Enabled = True
		pnv_selected_value_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		pnv_selected_value_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		pnv_selected_value_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		pnv_selected_value_tb.ReadOnly = True
		pnv_selected_value_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		pnv_selected_value_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		pnv_selected_value_tb.Multiline = True
		pnv_selected_value_tb.WordWrap = True
		pnv_selected_value_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['parameter_names_tab'].Controls.Add(pnv_selected_value_tb)
		ui.ModControls['pnv_selected_value_tb'] = pnv_selected_value_tb
		pnv_values_grid = ModDataGridView()
		pnv_values_grid.Name = 'pnv_values_grid'
		pnv_values_grid.Size = ModUiTools.GetSizeDefinition(315,256)
		pnv_values_grid.Location = ModUiTools.GetLocationDefinition(548,3)
		pnv_values_grid.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		pnv_values_grid.Dock = ModUiTools.GetDockStyleDefinition('None')
		pnv_values_grid.Enabled = True
		pnv_values_grid.BackgroundColor = ModUiTools.GetColorDefinition(-1)
		pnv_values_grid.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		pnv_values_grid.AllowUserToAddRows = False
		pnv_values_grid.AllowUserToDeleteRows = False
		pnv_values_grid.AllowUserToResizeColumns = True
		pnv_values_grid.AllowUserToResizeRows = False
		pnv_values_grid.ColumnHeadersVisible = True
		pnv_values_grid.RowHeadersVisible = False
		pnv_values_grid.GridColor = ModUiTools.GetColorDefinition(-1)
		pnv_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('ValuesClm', 'DataGridViewTextBoxCell', True, 100, 307, 5, 'Fill', 'U2VsZWN0IGEgVmFsdWUgdG8gdmlldyBkZXRhaWxzOg=='))
		pnv_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('LogIds', 'DataGridViewTextBoxCell', True, 100, 5, 2, 'NotSet', 'TG9nSWRz'))
		pnv_values_grid.CellClick += lambda s,e: self.pnv_values_grid_clicked()
		result_tabs.TabPages['parameter_names_tab'].Controls.Add(pnv_values_grid)
		ui.ModControls['pnv_values_grid'] = pnv_values_grid
		mod_label_5 = ModLabel()
		mod_label_5.Name = 'mod_label_5'
		mod_label_5.Size = ModUiTools.GetSizeDefinition(254,17)
		mod_label_5.Location = ModUiTools.GetLocationDefinition(5,3)
		mod_label_5.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_5.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_5.Enabled = True
		mod_label_5.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_5.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_5.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_5.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_5.Text =  Tools.Base64Decode('VGhlIGZvbGxvd2luZyBob3N0cyB3ZXJlIGZvdW5kIGluIHRoZSBsb2dzLg==')
		result_tabs.TabPages['parameter_names_tab'].Controls.Add(mod_label_5)
		ui.ModControls['mod_label_5'] = mod_label_5
		pnv_selected_parameter_tb = ModTextBox()
		pnv_selected_parameter_tb.Name = 'pnv_selected_parameter_tb'
		pnv_selected_parameter_tb.Size = ModUiTools.GetSizeDefinition(277,32)
		pnv_selected_parameter_tb.Location = ModUiTools.GetLocationDefinition(265,265)
		pnv_selected_parameter_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		pnv_selected_parameter_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		pnv_selected_parameter_tb.Enabled = True
		pnv_selected_parameter_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		pnv_selected_parameter_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		pnv_selected_parameter_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		pnv_selected_parameter_tb.ReadOnly = True
		pnv_selected_parameter_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		pnv_selected_parameter_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		pnv_selected_parameter_tb.Multiline = True
		pnv_selected_parameter_tb.WordWrap = True
		pnv_selected_parameter_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['parameter_names_tab'].Controls.Add(pnv_selected_parameter_tb)
		ui.ModControls['pnv_selected_parameter_tb'] = pnv_selected_parameter_tb
		pnv_selected_host_tb = ModTextBox()
		pnv_selected_host_tb.Name = 'pnv_selected_host_tb'
		pnv_selected_host_tb.Size = ModUiTools.GetSizeDefinition(254,32)
		pnv_selected_host_tb.Location = ModUiTools.GetLocationDefinition(5,416)
		pnv_selected_host_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		pnv_selected_host_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		pnv_selected_host_tb.Enabled = True
		pnv_selected_host_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		pnv_selected_host_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		pnv_selected_host_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		pnv_selected_host_tb.ReadOnly = True
		pnv_selected_host_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		pnv_selected_host_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		pnv_selected_host_tb.Multiline = True
		pnv_selected_host_tb.WordWrap = True
		pnv_selected_host_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['parameter_names_tab'].Controls.Add(pnv_selected_host_tb)
		ui.ModControls['pnv_selected_host_tb'] = pnv_selected_host_tb
		pnv_sections_grid = ModDataGridView()
		pnv_sections_grid.Name = 'pnv_sections_grid'
		pnv_sections_grid.Size = ModUiTools.GetSizeDefinition(277,145)
		pnv_sections_grid.Location = ModUiTools.GetLocationDefinition(265,303)
		pnv_sections_grid.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		pnv_sections_grid.Dock = ModUiTools.GetDockStyleDefinition('None')
		pnv_sections_grid.Enabled = True
		pnv_sections_grid.BackgroundColor = ModUiTools.GetColorDefinition(-1)
		pnv_sections_grid.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		pnv_sections_grid.AllowUserToAddRows = False
		pnv_sections_grid.AllowUserToDeleteRows = False
		pnv_sections_grid.AllowUserToResizeColumns = True
		pnv_sections_grid.AllowUserToResizeRows = False
		pnv_sections_grid.ColumnHeadersVisible = True
		pnv_sections_grid.RowHeadersVisible = False
		pnv_sections_grid.GridColor = ModUiTools.GetColorDefinition(-1)
		pnv_sections_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('SectionCln', 'DataGridViewTextBoxCell', True, 100, 274, 5, 'Fill', 'U2VsZWN0IGEgU2VjdGlvbg=='))
		pnv_sections_grid.CellClick += lambda s,e: self.pnv_sections_grid_clicked()
		result_tabs.TabPages['parameter_names_tab'].Controls.Add(pnv_sections_grid)
		ui.ModControls['pnv_sections_grid'] = pnv_sections_grid
		pnv_hosts_grid = ModDataGridView()
		pnv_hosts_grid.Name = 'pnv_hosts_grid'
		pnv_hosts_grid.Size = ModUiTools.GetSizeDefinition(254,387)
		pnv_hosts_grid.Location = ModUiTools.GetLocationDefinition(5,23)
		pnv_hosts_grid.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		pnv_hosts_grid.Dock = ModUiTools.GetDockStyleDefinition('None')
		pnv_hosts_grid.Enabled = True
		pnv_hosts_grid.BackgroundColor = ModUiTools.GetColorDefinition(-1)
		pnv_hosts_grid.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		pnv_hosts_grid.AllowUserToAddRows = False
		pnv_hosts_grid.AllowUserToDeleteRows = False
		pnv_hosts_grid.AllowUserToResizeColumns = True
		pnv_hosts_grid.AllowUserToResizeRows = False
		pnv_hosts_grid.ColumnHeadersVisible = True
		pnv_hosts_grid.RowHeadersVisible = False
		pnv_hosts_grid.GridColor = ModUiTools.GetColorDefinition(-1)
		pnv_hosts_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('HostCln', 'DataGridViewTextBoxCell', True, 100, 251, 5, 'Fill', 'U2VsZWN0IGEgSG9zdA=='))
		pnv_hosts_grid.CellClick += lambda s,e: self.pnv_hosts_grid_clicked()
		result_tabs.TabPages['parameter_names_tab'].Controls.Add(pnv_hosts_grid)
		ui.ModControls['pnv_hosts_grid'] = pnv_hosts_grid
		pnv_parameters_grid = ModDataGridView()
		pnv_parameters_grid.Name = 'pnv_parameters_grid'
		pnv_parameters_grid.Size = ModUiTools.GetSizeDefinition(277,256)
		pnv_parameters_grid.Location = ModUiTools.GetLocationDefinition(265,3)
		pnv_parameters_grid.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		pnv_parameters_grid.Dock = ModUiTools.GetDockStyleDefinition('None')
		pnv_parameters_grid.Enabled = True
		pnv_parameters_grid.BackgroundColor = ModUiTools.GetColorDefinition(-1)
		pnv_parameters_grid.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		pnv_parameters_grid.AllowUserToAddRows = False
		pnv_parameters_grid.AllowUserToDeleteRows = False
		pnv_parameters_grid.AllowUserToResizeColumns = True
		pnv_parameters_grid.AllowUserToResizeRows = False
		pnv_parameters_grid.ColumnHeadersVisible = True
		pnv_parameters_grid.RowHeadersVisible = False
		pnv_parameters_grid.GridColor = ModUiTools.GetColorDefinition(-1)
		pnv_parameters_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('ID', 'DataGridViewTextBoxCell', True, 100, 5, 2, 'NotSet', 'SUQ='))
		pnv_parameters_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('Parameter Names', 'DataGridViewTextBoxCell', True, 100, 269, 5, 'Fill', 'U2VsZWN0IGEgUGFyYW1ldGVyIE5hbWU='))
		pnv_parameters_grid.CellClick += lambda s,e: self.pnv_parameters_grid_clicked()
		result_tabs.TabPages['parameter_names_tab'].Controls.Add(pnv_parameters_grid)
		ui.ModControls['pnv_parameters_grid'] = pnv_parameters_grid
		result_tabs.TabPages.Add('encoded_parameters_tab', '  Encoded Parameter Values  ')
		mod_label_2 = ModLabel()
		mod_label_2.Name = 'mod_label_2'
		mod_label_2.Size = ModUiTools.GetSizeDefinition(205,17)
		mod_label_2.Location = ModUiTools.GetLocationDefinition(252,388)
		mod_label_2.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_2.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_2.Enabled = True
		mod_label_2.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_2.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_2.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_2.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_2.Text =  Tools.Base64Decode('UGFyYW1ldGVycyBuYW1lcyBjb250YWluaW5nIHRoaXMgdmFsdWU6')
		result_tabs.TabPages['encoded_parameters_tab'].Controls.Add(mod_label_2)
		ui.ModControls['mod_label_2'] = mod_label_2
		enc_parameter_names_tb = ModTextBox()
		enc_parameter_names_tb.Name = 'enc_parameter_names_tb'
		enc_parameter_names_tb.Size = ModUiTools.GetSizeDefinition(270,41)
		enc_parameter_names_tb.Location = ModUiTools.GetLocationDefinition(251,408)
		enc_parameter_names_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		enc_parameter_names_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		enc_parameter_names_tb.Enabled = True
		enc_parameter_names_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		enc_parameter_names_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		enc_parameter_names_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		enc_parameter_names_tb.ReadOnly = True
		enc_parameter_names_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		enc_parameter_names_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		enc_parameter_names_tb.Multiline = True
		enc_parameter_names_tb.WordWrap = True
		enc_parameter_names_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['encoded_parameters_tab'].Controls.Add(enc_parameter_names_tb)
		ui.ModControls['enc_parameter_names_tb'] = enc_parameter_names_tb
		mod_label_3 = ModLabel()
		mod_label_3.Name = 'mod_label_3'
		mod_label_3.Size = ModUiTools.GetSizeDefinition(167,14)
		mod_label_3.Location = ModUiTools.GetLocationDefinition(251,9)
		mod_label_3.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_3.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_3.Enabled = True
		mod_label_3.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_3.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_3.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_3.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_3.Text =  Tools.Base64Decode('U2VsZWN0IGFueSBpdGVtIHRvIHZpZXcgZGV0YWlsczo=')
		result_tabs.TabPages['encoded_parameters_tab'].Controls.Add(mod_label_3)
		ui.ModControls['mod_label_3'] = mod_label_3
		mod_label_4 = ModLabel()
		mod_label_4.Name = 'mod_label_4'
		mod_label_4.Size = ModUiTools.GetSizeDefinition(301,18)
		mod_label_4.Location = ModUiTools.GetLocationDefinition(527,388)
		mod_label_4.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_4.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_4.Enabled = True
		mod_label_4.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_4.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_4.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_4.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_4.Text =  Tools.Base64Decode('UHJveHkgTG9nIElEcyBvZiBSZXF1ZXN0cy9SZXNwb25zZXMgY29udGFpbmluZyB0aGlzIHZhbHVlOg==')
		result_tabs.TabPages['encoded_parameters_tab'].Controls.Add(mod_label_4)
		ui.ModControls['mod_label_4'] = mod_label_4
		enc_log_ids_tb = ModTextBox()
		enc_log_ids_tb.Name = 'enc_log_ids_tb'
		enc_log_ids_tb.Size = ModUiTools.GetSizeDefinition(336,38)
		enc_log_ids_tb.Location = ModUiTools.GetLocationDefinition(527,409)
		enc_log_ids_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		enc_log_ids_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		enc_log_ids_tb.Enabled = True
		enc_log_ids_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		enc_log_ids_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		enc_log_ids_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		enc_log_ids_tb.ReadOnly = True
		enc_log_ids_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		enc_log_ids_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		enc_log_ids_tb.Multiline = True
		enc_log_ids_tb.WordWrap = True
		enc_log_ids_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['encoded_parameters_tab'].Controls.Add(enc_log_ids_tb)
		ui.ModControls['enc_log_ids_tb'] = enc_log_ids_tb
		mod_label_6 = ModLabel()
		mod_label_6.Name = 'mod_label_6'
		mod_label_6.Size = ModUiTools.GetSizeDefinition(100,14)
		mod_label_6.Location = ModUiTools.GetLocationDefinition(527,300)
		mod_label_6.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_6.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_6.Enabled = True
		mod_label_6.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_6.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_6.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_6.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_6.Text =  Tools.Base64Decode('RGVjb2RlZCBWYWx1ZTo=')
		result_tabs.TabPages['encoded_parameters_tab'].Controls.Add(mod_label_6)
		ui.ModControls['mod_label_6'] = mod_label_6
		mod_label_7 = ModLabel()
		mod_label_7.Name = 'mod_label_7'
		mod_label_7.Size = ModUiTools.GetSizeDefinition(100,14)
		mod_label_7.Location = ModUiTools.GetLocationDefinition(251,300)
		mod_label_7.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_7.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_7.Enabled = True
		mod_label_7.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_7.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_7.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_7.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_7.Text =  Tools.Base64Decode('T3JpZ25hbCBWYWx1ZTo=')
		result_tabs.TabPages['encoded_parameters_tab'].Controls.Add(mod_label_7)
		ui.ModControls['mod_label_7'] = mod_label_7
		enc_decoded_value_tb = ModTextBox()
		enc_decoded_value_tb.Name = 'enc_decoded_value_tb'
		enc_decoded_value_tb.Size = ModUiTools.GetSizeDefinition(336,68)
		enc_decoded_value_tb.Location = ModUiTools.GetLocationDefinition(527,317)
		enc_decoded_value_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		enc_decoded_value_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		enc_decoded_value_tb.Enabled = True
		enc_decoded_value_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		enc_decoded_value_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		enc_decoded_value_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		enc_decoded_value_tb.ReadOnly = True
		enc_decoded_value_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		enc_decoded_value_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		enc_decoded_value_tb.Multiline = True
		enc_decoded_value_tb.WordWrap = True
		enc_decoded_value_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['encoded_parameters_tab'].Controls.Add(enc_decoded_value_tb)
		ui.ModControls['enc_decoded_value_tb'] = enc_decoded_value_tb
		enc_original_value_tb = ModTextBox()
		enc_original_value_tb.Name = 'enc_original_value_tb'
		enc_original_value_tb.Size = ModUiTools.GetSizeDefinition(270,68)
		enc_original_value_tb.Location = ModUiTools.GetLocationDefinition(251,317)
		enc_original_value_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		enc_original_value_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		enc_original_value_tb.Enabled = True
		enc_original_value_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		enc_original_value_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		enc_original_value_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		enc_original_value_tb.ReadOnly = True
		enc_original_value_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		enc_original_value_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		enc_original_value_tb.Multiline = True
		enc_original_value_tb.WordWrap = True
		enc_original_value_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['encoded_parameters_tab'].Controls.Add(enc_original_value_tb)
		ui.ModControls['enc_original_value_tb'] = enc_original_value_tb
		enc_values_grid = ModDataGridView()
		enc_values_grid.Name = 'enc_values_grid'
		enc_values_grid.Size = ModUiTools.GetSizeDefinition(612,268)
		enc_values_grid.Location = ModUiTools.GetLocationDefinition(251,26)
		enc_values_grid.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		enc_values_grid.Dock = ModUiTools.GetDockStyleDefinition('None')
		enc_values_grid.Enabled = True
		enc_values_grid.BackgroundColor = ModUiTools.GetColorDefinition(-1)
		enc_values_grid.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		enc_values_grid.AllowUserToAddRows = False
		enc_values_grid.AllowUserToDeleteRows = False
		enc_values_grid.AllowUserToResizeColumns = True
		enc_values_grid.AllowUserToResizeRows = False
		enc_values_grid.ColumnHeadersVisible = True
		enc_values_grid.RowHeadersVisible = False
		enc_values_grid.GridColor = ModUiTools.GetColorDefinition(-1)
		enc_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('OriginalValue', 'DataGridViewTextBoxCell', True, 100, 265, 5, 'Fill', 'T3JpZ2luYWxWYWx1ZQ=='))
		enc_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('Encoding Type', 'DataGridViewTextBoxCell', True, 100, 70, 70, 'None', 'RW5jb2Rpbmc='))
		enc_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('Decoded Value', 'DataGridViewTextBoxCell', True, 100, 264, 5, 'Fill', 'RGVjb2RlZCBWYWx1ZQ=='))
		enc_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('LogIds', 'DataGridViewTextBoxCell', True, 100, 5, 2, 'NotSet', 'TG9nSWRz'))
		enc_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('ParameterNames', 'DataGridViewTextBoxCell', False, 100, 5, 2, 'NotSet', 'UGFyYW1ldGVyTmFtZXM='))
		enc_values_grid.CellClick += lambda s,e: self.enc_values_grid_click()
		result_tabs.TabPages['encoded_parameters_tab'].Controls.Add(enc_values_grid)
		ui.ModControls['enc_values_grid'] = enc_values_grid
		enc_selected_host_tb = ModTextBox()
		enc_selected_host_tb.Name = 'enc_selected_host_tb'
		enc_selected_host_tb.Size = ModUiTools.GetSizeDefinition(245,39)
		enc_selected_host_tb.Location = ModUiTools.GetLocationDefinition(0,408)
		enc_selected_host_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		enc_selected_host_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		enc_selected_host_tb.Enabled = True
		enc_selected_host_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		enc_selected_host_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		enc_selected_host_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		enc_selected_host_tb.ReadOnly = True
		enc_selected_host_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		enc_selected_host_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		enc_selected_host_tb.Multiline = True
		enc_selected_host_tb.WordWrap = True
		enc_selected_host_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['encoded_parameters_tab'].Controls.Add(enc_selected_host_tb)
		ui.ModControls['enc_selected_host_tb'] = enc_selected_host_tb
		enc_hosts_grid = ModDataGridView()
		enc_hosts_grid.Name = 'enc_hosts_grid'
		enc_hosts_grid.Size = ModUiTools.GetSizeDefinition(242,376)
		enc_hosts_grid.Location = ModUiTools.GetLocationDefinition(3,26)
		enc_hosts_grid.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		enc_hosts_grid.Dock = ModUiTools.GetDockStyleDefinition('None')
		enc_hosts_grid.Enabled = True
		enc_hosts_grid.BackgroundColor = ModUiTools.GetColorDefinition(-1)
		enc_hosts_grid.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		enc_hosts_grid.AllowUserToAddRows = False
		enc_hosts_grid.AllowUserToDeleteRows = False
		enc_hosts_grid.AllowUserToResizeColumns = True
		enc_hosts_grid.AllowUserToResizeRows = False
		enc_hosts_grid.ColumnHeadersVisible = True
		enc_hosts_grid.RowHeadersVisible = False
		enc_hosts_grid.GridColor = ModUiTools.GetColorDefinition(-1)
		enc_hosts_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('Host', 'DataGridViewTextBoxCell', True, 100, 239, 5, 'Fill', 'U2VsZWN0IGEgSG9zdA=='))
		enc_hosts_grid.CellClick += lambda s,e: self.enc_hosts_grid_click()
		result_tabs.TabPages['encoded_parameters_tab'].Controls.Add(enc_hosts_grid)
		ui.ModControls['enc_hosts_grid'] = enc_hosts_grid
		mod_label_8 = ModLabel()
		mod_label_8.Name = 'mod_label_8'
		mod_label_8.Size = ModUiTools.GetSizeDefinition(203,14)
		mod_label_8.Location = ModUiTools.GetLocationDefinition(3,9)
		mod_label_8.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_8.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_8.Enabled = True
		mod_label_8.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_8.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_8.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_8.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_8.Text =  Tools.Base64Decode('VGhlIGZvbGxvd2luZyBob3N0cyBoYXZlIGVuY29kZWQgdmFsdWVzOg==')
		result_tabs.TabPages['encoded_parameters_tab'].Controls.Add(mod_label_8)
		ui.ModControls['mod_label_8'] = mod_label_8
		result_tabs.TabPages.Add('hashed_parameters_tab', '  Hashed Parameter Values  ')
		mod_label_9 = ModLabel()
		mod_label_9.Name = 'mod_label_9'
		mod_label_9.Size = ModUiTools.GetSizeDefinition(205,17)
		mod_label_9.Location = ModUiTools.GetLocationDefinition(252,388)
		mod_label_9.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_9.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_9.Enabled = True
		mod_label_9.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_9.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_9.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_9.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_9.Text =  Tools.Base64Decode('UGFyYW1ldGVycyBuYW1lcyBjb250YWluaW5nIHRoaXMgdmFsdWU6')
		result_tabs.TabPages['hashed_parameters_tab'].Controls.Add(mod_label_9)
		ui.ModControls['mod_label_9'] = mod_label_9
		hashed_parameter_names_tb = ModTextBox()
		hashed_parameter_names_tb.Name = 'hashed_parameter_names_tb'
		hashed_parameter_names_tb.Size = ModUiTools.GetSizeDefinition(270,41)
		hashed_parameter_names_tb.Location = ModUiTools.GetLocationDefinition(251,408)
		hashed_parameter_names_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		hashed_parameter_names_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		hashed_parameter_names_tb.Enabled = True
		hashed_parameter_names_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		hashed_parameter_names_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		hashed_parameter_names_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		hashed_parameter_names_tb.ReadOnly = True
		hashed_parameter_names_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		hashed_parameter_names_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		hashed_parameter_names_tb.Multiline = True
		hashed_parameter_names_tb.WordWrap = True
		hashed_parameter_names_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['hashed_parameters_tab'].Controls.Add(hashed_parameter_names_tb)
		ui.ModControls['hashed_parameter_names_tb'] = hashed_parameter_names_tb
		mod_label_10 = ModLabel()
		mod_label_10.Name = 'mod_label_10'
		mod_label_10.Size = ModUiTools.GetSizeDefinition(167,14)
		mod_label_10.Location = ModUiTools.GetLocationDefinition(251,9)
		mod_label_10.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_10.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_10.Enabled = True
		mod_label_10.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_10.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_10.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_10.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_10.Text =  Tools.Base64Decode('U2VsZWN0IGFueSBpdGVtIHRvIHZpZXcgZGV0YWlsczo=')
		result_tabs.TabPages['hashed_parameters_tab'].Controls.Add(mod_label_10)
		ui.ModControls['mod_label_10'] = mod_label_10
		mod_label_11 = ModLabel()
		mod_label_11.Name = 'mod_label_11'
		mod_label_11.Size = ModUiTools.GetSizeDefinition(301,18)
		mod_label_11.Location = ModUiTools.GetLocationDefinition(527,388)
		mod_label_11.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_11.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_11.Enabled = True
		mod_label_11.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_11.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_11.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_11.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_11.Text =  Tools.Base64Decode('UHJveHkgTG9nIElEcyBvZiBSZXF1ZXN0cy9SZXNwb25zZXMgY29udGFpbmluZyB0aGlzIHZhbHVlOg==')
		result_tabs.TabPages['hashed_parameters_tab'].Controls.Add(mod_label_11)
		ui.ModControls['mod_label_11'] = mod_label_11
		hashed_log_ids_tb = ModTextBox()
		hashed_log_ids_tb.Name = 'hashed_log_ids_tb'
		hashed_log_ids_tb.Size = ModUiTools.GetSizeDefinition(336,38)
		hashed_log_ids_tb.Location = ModUiTools.GetLocationDefinition(527,409)
		hashed_log_ids_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		hashed_log_ids_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		hashed_log_ids_tb.Enabled = True
		hashed_log_ids_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		hashed_log_ids_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		hashed_log_ids_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		hashed_log_ids_tb.ReadOnly = True
		hashed_log_ids_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		hashed_log_ids_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		hashed_log_ids_tb.Multiline = True
		hashed_log_ids_tb.WordWrap = True
		hashed_log_ids_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['hashed_parameters_tab'].Controls.Add(hashed_log_ids_tb)
		ui.ModControls['hashed_log_ids_tb'] = hashed_log_ids_tb
		mod_label_12 = ModLabel()
		mod_label_12.Name = 'mod_label_12'
		mod_label_12.Size = ModUiTools.GetSizeDefinition(100,14)
		mod_label_12.Location = ModUiTools.GetLocationDefinition(527,300)
		mod_label_12.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_12.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_12.Enabled = True
		mod_label_12.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_12.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_12.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_12.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_12.Text =  Tools.Base64Decode('Q3JhY2tlZCBWYWx1ZTo=')
		result_tabs.TabPages['hashed_parameters_tab'].Controls.Add(mod_label_12)
		ui.ModControls['mod_label_12'] = mod_label_12
		mod_label_13 = ModLabel()
		mod_label_13.Name = 'mod_label_13'
		mod_label_13.Size = ModUiTools.GetSizeDefinition(100,14)
		mod_label_13.Location = ModUiTools.GetLocationDefinition(251,300)
		mod_label_13.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_13.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_13.Enabled = True
		mod_label_13.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_13.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_13.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_13.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_13.Text =  Tools.Base64Decode('SGFzaGVkIFZhbHVlOg==')
		result_tabs.TabPages['hashed_parameters_tab'].Controls.Add(mod_label_13)
		ui.ModControls['mod_label_13'] = mod_label_13
		hashed_cracked_value_tb = ModTextBox()
		hashed_cracked_value_tb.Name = 'hashed_cracked_value_tb'
		hashed_cracked_value_tb.Size = ModUiTools.GetSizeDefinition(336,68)
		hashed_cracked_value_tb.Location = ModUiTools.GetLocationDefinition(527,317)
		hashed_cracked_value_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		hashed_cracked_value_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		hashed_cracked_value_tb.Enabled = True
		hashed_cracked_value_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		hashed_cracked_value_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		hashed_cracked_value_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		hashed_cracked_value_tb.ReadOnly = True
		hashed_cracked_value_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		hashed_cracked_value_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		hashed_cracked_value_tb.Multiline = True
		hashed_cracked_value_tb.WordWrap = True
		hashed_cracked_value_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['hashed_parameters_tab'].Controls.Add(hashed_cracked_value_tb)
		ui.ModControls['hashed_cracked_value_tb'] = hashed_cracked_value_tb
		hashed_original_value_tb = ModTextBox()
		hashed_original_value_tb.Name = 'hashed_original_value_tb'
		hashed_original_value_tb.Size = ModUiTools.GetSizeDefinition(270,68)
		hashed_original_value_tb.Location = ModUiTools.GetLocationDefinition(251,317)
		hashed_original_value_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		hashed_original_value_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		hashed_original_value_tb.Enabled = True
		hashed_original_value_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		hashed_original_value_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		hashed_original_value_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		hashed_original_value_tb.ReadOnly = True
		hashed_original_value_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		hashed_original_value_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		hashed_original_value_tb.Multiline = True
		hashed_original_value_tb.WordWrap = True
		hashed_original_value_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['hashed_parameters_tab'].Controls.Add(hashed_original_value_tb)
		ui.ModControls['hashed_original_value_tb'] = hashed_original_value_tb
		hashed_values_grid = ModDataGridView()
		hashed_values_grid.Name = 'hashed_values_grid'
		hashed_values_grid.Size = ModUiTools.GetSizeDefinition(612,268)
		hashed_values_grid.Location = ModUiTools.GetLocationDefinition(251,26)
		hashed_values_grid.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		hashed_values_grid.Dock = ModUiTools.GetDockStyleDefinition('None')
		hashed_values_grid.Enabled = True
		hashed_values_grid.BackgroundColor = ModUiTools.GetColorDefinition(-1)
		hashed_values_grid.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		hashed_values_grid.AllowUserToAddRows = False
		hashed_values_grid.AllowUserToDeleteRows = False
		hashed_values_grid.AllowUserToResizeColumns = True
		hashed_values_grid.AllowUserToResizeRows = False
		hashed_values_grid.ColumnHeadersVisible = True
		hashed_values_grid.RowHeadersVisible = False
		hashed_values_grid.GridColor = ModUiTools.GetColorDefinition(-1)
		hashed_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('OriginalValue', 'DataGridViewTextBoxCell', True, 100, 265, 5, 'Fill', 'T3JpZ2luYWwgSGFzaGVkIFZhbHVl'))
		hashed_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('Encoding Type', 'DataGridViewTextBoxCell', True, 100, 70, 70, 'None', 'SGFzaCBUeXBl'))
		hashed_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('Decoded Value', 'DataGridViewTextBoxCell', True, 100, 264, 5, 'Fill', 'Q3JhY2tlZCBWYWx1ZQ=='))
		hashed_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('LogIds', 'DataGridViewTextBoxCell', True, 100, 5, 2, 'NotSet', 'TG9nSWRz'))
		hashed_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('ParameterNames', 'DataGridViewTextBoxCell', False, 100, 5, 2, 'NotSet', 'UGFyYW1ldGVyTmFtZXM='))
		hashed_values_grid.CellClick += lambda s,e: self.hashed_values_grid_click()
		result_tabs.TabPages['hashed_parameters_tab'].Controls.Add(hashed_values_grid)
		ui.ModControls['hashed_values_grid'] = hashed_values_grid
		hashed_selected_host_tb = ModTextBox()
		hashed_selected_host_tb.Name = 'hashed_selected_host_tb'
		hashed_selected_host_tb.Size = ModUiTools.GetSizeDefinition(242,39)
		hashed_selected_host_tb.Location = ModUiTools.GetLocationDefinition(3,408)
		hashed_selected_host_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		hashed_selected_host_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		hashed_selected_host_tb.Enabled = True
		hashed_selected_host_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		hashed_selected_host_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		hashed_selected_host_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		hashed_selected_host_tb.ReadOnly = True
		hashed_selected_host_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		hashed_selected_host_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		hashed_selected_host_tb.Multiline = True
		hashed_selected_host_tb.WordWrap = True
		hashed_selected_host_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['hashed_parameters_tab'].Controls.Add(hashed_selected_host_tb)
		ui.ModControls['hashed_selected_host_tb'] = hashed_selected_host_tb
		hashed_hosts_grid = ModDataGridView()
		hashed_hosts_grid.Name = 'hashed_hosts_grid'
		hashed_hosts_grid.Size = ModUiTools.GetSizeDefinition(242,376)
		hashed_hosts_grid.Location = ModUiTools.GetLocationDefinition(3,26)
		hashed_hosts_grid.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		hashed_hosts_grid.Dock = ModUiTools.GetDockStyleDefinition('None')
		hashed_hosts_grid.Enabled = True
		hashed_hosts_grid.BackgroundColor = ModUiTools.GetColorDefinition(-1)
		hashed_hosts_grid.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		hashed_hosts_grid.AllowUserToAddRows = False
		hashed_hosts_grid.AllowUserToDeleteRows = False
		hashed_hosts_grid.AllowUserToResizeColumns = True
		hashed_hosts_grid.AllowUserToResizeRows = False
		hashed_hosts_grid.ColumnHeadersVisible = True
		hashed_hosts_grid.RowHeadersVisible = False
		hashed_hosts_grid.GridColor = ModUiTools.GetColorDefinition(-1)
		hashed_hosts_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('Host', 'DataGridViewTextBoxCell', True, 100, 239, 5, 'Fill', 'U2VsZWN0IGEgSG9zdA=='))
		hashed_hosts_grid.CellClick += lambda s,e: self.hashed_hosts_grid_click()
		result_tabs.TabPages['hashed_parameters_tab'].Controls.Add(hashed_hosts_grid)
		ui.ModControls['hashed_hosts_grid'] = hashed_hosts_grid
		mod_label_14 = ModLabel()
		mod_label_14.Name = 'mod_label_14'
		mod_label_14.Size = ModUiTools.GetSizeDefinition(203,14)
		mod_label_14.Location = ModUiTools.GetLocationDefinition(3,9)
		mod_label_14.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_14.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_14.Enabled = True
		mod_label_14.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_14.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_14.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_14.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_14.Text =  Tools.Base64Decode('VGhlIGZvbGxvd2luZyBob3N0cyBoYXZlIGhhc2hlZCB2YWx1ZXM6')
		result_tabs.TabPages['hashed_parameters_tab'].Controls.Add(mod_label_14)
		ui.ModControls['mod_label_14'] = mod_label_14
		result_tabs.TabPages.Add('stored_reflections_tab', '  Potential Stored XSS Candidates  ')
		mod_label_15 = ModLabel()
		mod_label_15.Name = 'mod_label_15'
		mod_label_15.Size = ModUiTools.GetSizeDefinition(250,17)
		mod_label_15.Location = ModUiTools.GetLocationDefinition(251,368)
		mod_label_15.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_15.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_15.Enabled = True
		mod_label_15.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_15.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_15.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_15.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_15.Text =  Tools.Base64Decode('UHJveHkgTG9nIElEcyBvZiBSZXF1ZXN0cyBoYXZpbmcgdGhpcyBQYXJhbWV0ZXI6')
		result_tabs.TabPages['stored_reflections_tab'].Controls.Add(mod_label_15)
		ui.ModControls['mod_label_15'] = mod_label_15
		sr_request_log_ids_tb = ModTextBox()
		sr_request_log_ids_tb.Name = 'sr_request_log_ids_tb'
		sr_request_log_ids_tb.Size = ModUiTools.GetSizeDefinition(270,61)
		sr_request_log_ids_tb.Location = ModUiTools.GetLocationDefinition(251,388)
		sr_request_log_ids_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		sr_request_log_ids_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		sr_request_log_ids_tb.Enabled = True
		sr_request_log_ids_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		sr_request_log_ids_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		sr_request_log_ids_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		sr_request_log_ids_tb.ReadOnly = True
		sr_request_log_ids_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		sr_request_log_ids_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		sr_request_log_ids_tb.Multiline = True
		sr_request_log_ids_tb.WordWrap = True
		sr_request_log_ids_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['stored_reflections_tab'].Controls.Add(sr_request_log_ids_tb)
		ui.ModControls['sr_request_log_ids_tb'] = sr_request_log_ids_tb
		mod_label_16 = ModLabel()
		mod_label_16.Name = 'mod_label_16'
		mod_label_16.Size = ModUiTools.GetSizeDefinition(167,14)
		mod_label_16.Location = ModUiTools.GetLocationDefinition(251,9)
		mod_label_16.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_16.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_16.Enabled = True
		mod_label_16.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_16.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_16.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_16.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_16.Text =  Tools.Base64Decode('U2VsZWN0IGFueSBpdGVtIHRvIHZpZXcgZGV0YWlsczo=')
		result_tabs.TabPages['stored_reflections_tab'].Controls.Add(mod_label_16)
		ui.ModControls['mod_label_16'] = mod_label_16
		mod_label_17 = ModLabel()
		mod_label_17.Name = 'mod_label_17'
		mod_label_17.Size = ModUiTools.GetSizeDefinition(307,18)
		mod_label_17.Location = ModUiTools.GetLocationDefinition(527,368)
		mod_label_17.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_17.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_17.Enabled = True
		mod_label_17.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_17.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_17.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_17.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_17.Text =  Tools.Base64Decode('UHJveHkgTG9nIElEcyBvZiBSZXNwb25zZXMgaGF2aW5nIHN0b3JlZCByZWZsZWN0aW9uIG9mIHZhbHVlOg==')
		result_tabs.TabPages['stored_reflections_tab'].Controls.Add(mod_label_17)
		ui.ModControls['mod_label_17'] = mod_label_17
		sr_response_log_ids_tb = ModTextBox()
		sr_response_log_ids_tb.Name = 'sr_response_log_ids_tb'
		sr_response_log_ids_tb.Size = ModUiTools.GetSizeDefinition(336,58)
		sr_response_log_ids_tb.Location = ModUiTools.GetLocationDefinition(527,389)
		sr_response_log_ids_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		sr_response_log_ids_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		sr_response_log_ids_tb.Enabled = True
		sr_response_log_ids_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		sr_response_log_ids_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		sr_response_log_ids_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		sr_response_log_ids_tb.ReadOnly = True
		sr_response_log_ids_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		sr_response_log_ids_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		sr_response_log_ids_tb.Multiline = True
		sr_response_log_ids_tb.WordWrap = True
		sr_response_log_ids_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['stored_reflections_tab'].Controls.Add(sr_response_log_ids_tb)
		ui.ModControls['sr_response_log_ids_tb'] = sr_response_log_ids_tb
		mod_label_18 = ModLabel()
		mod_label_18.Name = 'mod_label_18'
		mod_label_18.Size = ModUiTools.GetSizeDefinition(100,14)
		mod_label_18.Location = ModUiTools.GetLocationDefinition(527,300)
		mod_label_18.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_18.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_18.Enabled = True
		mod_label_18.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_18.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_18.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_18.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_18.Text =  Tools.Base64Decode('UmVmbGVjdGVkIFZhbHVlOg==')
		result_tabs.TabPages['stored_reflections_tab'].Controls.Add(mod_label_18)
		ui.ModControls['mod_label_18'] = mod_label_18
		mod_label_19 = ModLabel()
		mod_label_19.Name = 'mod_label_19'
		mod_label_19.Size = ModUiTools.GetSizeDefinition(100,14)
		mod_label_19.Location = ModUiTools.GetLocationDefinition(251,300)
		mod_label_19.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_19.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_19.Enabled = True
		mod_label_19.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_19.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_19.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_19.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_19.Text =  Tools.Base64Decode('UGFyYW1ldGVyIE5hbWU6')
		result_tabs.TabPages['stored_reflections_tab'].Controls.Add(mod_label_19)
		ui.ModControls['mod_label_19'] = mod_label_19
		sr_value_tb = ModTextBox()
		sr_value_tb.Name = 'sr_value_tb'
		sr_value_tb.Size = ModUiTools.GetSizeDefinition(336,48)
		sr_value_tb.Location = ModUiTools.GetLocationDefinition(527,317)
		sr_value_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		sr_value_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		sr_value_tb.Enabled = True
		sr_value_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		sr_value_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		sr_value_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		sr_value_tb.ReadOnly = True
		sr_value_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		sr_value_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		sr_value_tb.Multiline = True
		sr_value_tb.WordWrap = True
		sr_value_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['stored_reflections_tab'].Controls.Add(sr_value_tb)
		ui.ModControls['sr_value_tb'] = sr_value_tb
		sr_parameter_name_tb = ModTextBox()
		sr_parameter_name_tb.Name = 'sr_parameter_name_tb'
		sr_parameter_name_tb.Size = ModUiTools.GetSizeDefinition(270,48)
		sr_parameter_name_tb.Location = ModUiTools.GetLocationDefinition(251,317)
		sr_parameter_name_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		sr_parameter_name_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		sr_parameter_name_tb.Enabled = True
		sr_parameter_name_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		sr_parameter_name_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		sr_parameter_name_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		sr_parameter_name_tb.ReadOnly = True
		sr_parameter_name_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		sr_parameter_name_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		sr_parameter_name_tb.Multiline = True
		sr_parameter_name_tb.WordWrap = True
		sr_parameter_name_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['stored_reflections_tab'].Controls.Add(sr_parameter_name_tb)
		ui.ModControls['sr_parameter_name_tb'] = sr_parameter_name_tb
		sr_values_grid = ModDataGridView()
		sr_values_grid.Name = 'sr_values_grid'
		sr_values_grid.Size = ModUiTools.GetSizeDefinition(612,268)
		sr_values_grid.Location = ModUiTools.GetLocationDefinition(251,26)
		sr_values_grid.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		sr_values_grid.Dock = ModUiTools.GetDockStyleDefinition('None')
		sr_values_grid.Enabled = True
		sr_values_grid.BackgroundColor = ModUiTools.GetColorDefinition(-1)
		sr_values_grid.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		sr_values_grid.AllowUserToAddRows = False
		sr_values_grid.AllowUserToDeleteRows = False
		sr_values_grid.AllowUserToResizeColumns = True
		sr_values_grid.AllowUserToResizeRows = False
		sr_values_grid.ColumnHeadersVisible = True
		sr_values_grid.RowHeadersVisible = False
		sr_values_grid.GridColor = ModUiTools.GetColorDefinition(-1)
		sr_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('OriginalValue', 'DataGridViewTextBoxCell', True, 100, 100, 5, 'NotSet', 'UGFyYW1ldGVyIE5hbWU='))
		sr_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('Encoding Type', 'DataGridViewTextBoxCell', True, 100, 100, 5, 'NotSet', 'VmFsdWU='))
		sr_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('Decoded Value', 'DataGridViewTextBoxCell', True, 100, 205, 5, 'Fill', 'UmVxdWVzdHMgd2l0aCBQYXJhbWV0ZXI='))
		sr_values_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('LogIds', 'DataGridViewTextBoxCell', True, 100, 204, 2, 'Fill', 'UmVzcG9uc2VzIHdpdGggUmVmbGVjdGlvbg=='))
		sr_values_grid.CellClick += lambda s,e: self.sr_values_grid_click()
		result_tabs.TabPages['stored_reflections_tab'].Controls.Add(sr_values_grid)
		ui.ModControls['sr_values_grid'] = sr_values_grid
		sr_selected_host_tb = ModTextBox()
		sr_selected_host_tb.Name = 'sr_selected_host_tb'
		sr_selected_host_tb.Size = ModUiTools.GetSizeDefinition(242,39)
		sr_selected_host_tb.Location = ModUiTools.GetLocationDefinition(3,408)
		sr_selected_host_tb.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		sr_selected_host_tb.Dock = ModUiTools.GetDockStyleDefinition('None')
		sr_selected_host_tb.Enabled = True
		sr_selected_host_tb.BackColor = ModUiTools.GetColorDefinition(-1)
		sr_selected_host_tb.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		sr_selected_host_tb.BorderStyle = ModUiTools.GetBorderStyleDefinition('Fixed3D')
		sr_selected_host_tb.ReadOnly = True
		sr_selected_host_tb.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		sr_selected_host_tb.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		sr_selected_host_tb.Multiline = True
		sr_selected_host_tb.WordWrap = True
		sr_selected_host_tb.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		result_tabs.TabPages['stored_reflections_tab'].Controls.Add(sr_selected_host_tb)
		ui.ModControls['sr_selected_host_tb'] = sr_selected_host_tb
		sr_hosts_grid = ModDataGridView()
		sr_hosts_grid.Name = 'sr_hosts_grid'
		sr_hosts_grid.Size = ModUiTools.GetSizeDefinition(242,376)
		sr_hosts_grid.Location = ModUiTools.GetLocationDefinition(3,26)
		sr_hosts_grid.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		sr_hosts_grid.Dock = ModUiTools.GetDockStyleDefinition('None')
		sr_hosts_grid.Enabled = True
		sr_hosts_grid.BackgroundColor = ModUiTools.GetColorDefinition(-1)
		sr_hosts_grid.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		sr_hosts_grid.AllowUserToAddRows = False
		sr_hosts_grid.AllowUserToDeleteRows = False
		sr_hosts_grid.AllowUserToResizeColumns = True
		sr_hosts_grid.AllowUserToResizeRows = False
		sr_hosts_grid.ColumnHeadersVisible = True
		sr_hosts_grid.RowHeadersVisible = False
		sr_hosts_grid.GridColor = ModUiTools.GetColorDefinition(-1)
		sr_hosts_grid.Columns.Add(ModUiTools.GetDataGridViewColumnDefinition('Host', 'DataGridViewTextBoxCell', True, 100, 239, 5, 'Fill', 'U2VsZWN0IGEgSG9zdA=='))
		sr_hosts_grid.CellClick += lambda s,e: self.sr_hosts_grid_click()
		result_tabs.TabPages['stored_reflections_tab'].Controls.Add(sr_hosts_grid)
		ui.ModControls['sr_hosts_grid'] = sr_hosts_grid
		mod_label_20 = ModLabel()
		mod_label_20.Name = 'mod_label_20'
		mod_label_20.Size = ModUiTools.GetSizeDefinition(203,14)
		mod_label_20.Location = ModUiTools.GetLocationDefinition(3,9)
		mod_label_20.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_20.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_20.Enabled = True
		mod_label_20.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_20.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_20.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_20.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_20.Text =  Tools.Base64Decode('VGhlIGZvbGxvd2luZyBob3N0cyBoYXZlIGhhc2hlZCB2YWx1ZXM6')
		result_tabs.TabPages['stored_reflections_tab'].Controls.Add(mod_label_20)
		ui.ModControls['mod_label_20'] = mod_label_20
		result_tabs.TabPages.Add('interactive_testing_tab', '  Interactive Testing  ')
		mod_label_21 = ModLabel()
		mod_label_21.Name = 'mod_label_21'
		mod_label_21.Size = ModUiTools.GetSizeDefinition(830,135)
		mod_label_21.Location = ModUiTools.GetLocationDefinition(17,19)
		mod_label_21.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_label_21.Dock = ModUiTools.GetDockStyleDefinition('None')
		mod_label_21.Enabled = True
		mod_label_21.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_label_21.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_label_21.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_label_21.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_label_21.Text =  Tools.Base64Decode('VGhpcyBzZWN0aW9uIHdhcyBvcmlnaW5hbGx5IHBsYW5uZWQgdG8gaG9sZCB1dGlsaXRpZXMgdG8gcGVyZm9ybSBDU1JGIHRlc3RpbmcsIFByaXZpbGxlZ2UgRXNjYWxhdGlvbiB0ZXN0cyBhbmQgSGlkZGVuIFBhcmFtZXRlciBHdWVzc2luZyB0ZXN0cyBiYXNlZCBvbiB0aGUgaW5mb3JtYXRpb24gZm91bmQgaW4gdGhlIGFuYWx5c2lzIG9mIHRoZSBsb2cuDQoNCkhvd2V2ZXIgdG8gcHJvdmlkZSBhIG1vcmUgcm9idXN0IFVJIGZvciB0aGVzZSB0ZXN0cyB0aGVzZSBmdW5jdGlvbmFsaXR5IGhhdmUgYmVlbiBtb3ZlZCB0byB0aGUgSXJvbldBU1AgY29yZSBpdHNlbGYuDQpUbyBhY2Nlc3MgdGhlc2UgZmVhdHVyZXMgZ28gdG8gdGhlIExvZ3Mgc2VjdGlvbiBpbnNpZGUgSXJvbldBU1AsIGNsaWNrIG9uIHRoZSAnU2VhcmNoIGFuZCBBbmFseXplIExvZ3MnIGJ1dHRvbiB0aGVyZS4NCkFmdGVyIHlvdSBkbyBhIHNlYXJjaCwgY2xpY2sgb24gdGhlICdUZXN0IFNlbGVjdGVkIExvZ3MnIGJ1dHRvbiB0byBhY2Nlc3MgdGhlc2UgZmVhdHVyZXMu')
		result_tabs.TabPages['interactive_testing_tab'].Controls.Add(mod_label_21)
		ui.ModControls['mod_label_21'] = mod_label_21
		result_tabs.TabPages.Add('tab_page_21', '  Help  ')
		mod_text_box_21 = ModTextBox()
		mod_text_box_21.Name = 'mod_text_box_21'
		mod_text_box_21.Size = ModUiTools.GetSizeDefinition(861,446)
		mod_text_box_21.Location = ModUiTools.GetLocationDefinition(3,3)
		mod_text_box_21.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		mod_text_box_21.Dock = ModUiTools.GetDockStyleDefinition('Fill')
		mod_text_box_21.Enabled = True
		mod_text_box_21.BackColor = ModUiTools.GetColorDefinition(-986896)
		mod_text_box_21.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		mod_text_box_21.BorderStyle = ModUiTools.GetBorderStyleDefinition('None')
		mod_text_box_21.ReadOnly = True
		mod_text_box_21.ScrollBars = ModUiTools.GetScrollBarsDefinition('Vertical')
		mod_text_box_21.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		mod_text_box_21.Multiline = True
		mod_text_box_21.WordWrap = True
		mod_text_box_21.TextAlign = ModUiTools.GetTextAlignDefinition('Left')
		mod_text_box_21.Text =  Tools.Base64Decode('SEFXQVMgYW5hbHl6ZXMgeW91ciBQcm94eSBsb2dzIGFuZCBsb29rcyBmb3IgaW50ZXJlc3RpbmcgaW5mb3JtYXRpb24uIE9uY2UgdGhlIGFuYWx5c2lzIGlzIGNvbXBsZXRlIHRoZSByZXN1bHRzIGFyZSBzaG93biB0byB5b3UuDQpUaGUgcmVzdWx0cyBhcmVhIGhhcyB0aGUgZm9sbG93aW5nIHNlY3Rpb25zOg0KDQpQYXJhbWV0ZXIgTmFtZXMgYW5kIFZhbHVlczoNCj09PT09PT09PT09PT09PT09PT09PT09PT09PQ0KVGhpcyBzZWN0aW9uIGxpc3RzIGFsbCB0aGUgcGFyYW1ldGVyIG5hbWVzIGFuZCB2YWx1ZXMgZGlzY292ZXJlZCBmcm9tIHRoZSBsb2dzLiBUaGVzZSBhcmUgY2F0ZWdvcml6ZWQgYnkgdGhlIGhvc3RuYW1lcy4NClRoZSBsaXN0IG9mIGFsbCBob3N0cyBkaXNjb3ZlcmVkIGluIHRoZSBsb2dzIGlzIGRpc3BsYXllZCBpbiB0aGUgbGVmdC1tb3N0IGFyZWEuIFdoZW4geW91IGNsaWNrIG9uIGFueSBvZiB0aGUgbGlzdGVkIGhvc3RuYW1lcyB0aGVuIHRoZSBuYW1lcyBvZiBhbGwgdGhlIHBhcmFtZXRlcnMgYmVsb25naW5nIHRvIHRoYXQgaG9zdCBhcmUgc2hvd24uDQpXaGVuIHlvdSBjbGljayBvbiBhIHBhcmFtZXRlciBuYW1lLCB0aGUgc2VjdGlvbnMgaW4gd2hpY2ggdGhlc2UgcGFyYW1ldGVyIG5hbWVzIHdlcmUgZGlzY292ZXJlZCBpcyBzaG93bi4NCldoZW4geW91IGNsaWNrIG9uIG9uZSBvZiB0aGUgc2VjdGlvbnMgdGhlbiBhbGwgdGhlIHZhbHVlcyB0aGF0IHRoZSBzZWxlY3RlZCBwYXJhbWV0ZXIgaGFkIGluIHRoZSBzZWN0aW9uIGFyZSBsaXN0ZWQuDQoNClRoaXMgY2FuIGJlIGhlbHBmdWwgaW4gZ2V0IGEgcXVpY2sgb3ZlcnZpZXcgb2YgdGhlIHNpdGUgYW5kIHRvIGlkZW50aWZ5IHBhcmFtZXRlcnMgd2l0aCBpbnRlcmVzdGluZyBuYW1lcyBhbmQgdmFsdWVzLg0KDQpFbmNvZGVkIFBhcmFtZXRlciBWYWx1ZXM6DQo9PT09PT09PT09PT09PT09PT09PT09PT09DQpTb21ldGltZXMgcGFyYW1ldGVycyBjb3VsZCBoYXZlIHZhbHVlcyB0aGF0IGFyZSBlaXRoZXIgSGV4IG9yIEJhc2U2NCBlbmNvZGVkLiBJZiBIQVdBUyBpZGVudGlmaWVkIGFueSBwYXJhbWV0ZXJzIHdpdGggc3VjaCBlbmNvZGVkIHZhbHVlcyB0aGVuIGl0IGRlY29kZXMgdGhlbSBhbmQgbGlzdHMgdGhlbSBoZXJlLg0KQWdhaW4gdGhlIGZpbmRpbmdzIGFyZSBjYXRlZ29yaXplZCBieSBob3N0bmFtZS4gQ2xpY2sgb24gYSBob3N0bmFtZSB0byBzZWUgaWYgaXQgY29udGFpbmVkIGFueSBlbmNvZGVkIHBhcmFtZXRlciB2YWx1ZXMuDQpPbmx5IEhleCBhbmQgQmFzZTY0IGVuY29kaW5nIGRldGVjdGlvbiBhcmUgc3VwcG9ydGVkIGZvciBub3cuDQoNCkhhc2hlZCBQYXJhbWV0ZXIgVmFsdWVzOg0KPT09PT09PT09PT09PT09PT09PT09PT09DQpTb21ldGltZXMgcGFyYW1ldGVycyBjb3VsZCBoYXZlIHZhbHVlcyB0aGF0IGFyZSBTSEEgb3IgTUQ1IGhhc2hlcy4gSWYgSEFXQVMgaWRlbnRpZmllZCBhbnkgcGFyYW1ldGVycyB3aGljaCBsb29rIGxpa2UgaGFzaGVzIHRoZW4gaXQgdHJpZXMgdG8gY3JhY2sgdGhlbSBieSB1c2luZyB0aGUgbGlzdCBvZiBwYXJhbWV0ZXIgdmFsdWVzIGZyb20gdGhlIHNhbWUgaG9zdCBhcyBkaWN0aW9uYXJ5IGxpc3QuDQpJZiBIQVdBUyBpcyBhYmxlIHRvIGNyYWNrIGFueSBvZiB0aGVzZSBoYXNoZXMgdGhlbiBpdCBpbmNsdWRlcyB0aGUgY3JhY2tlZCB2YWx1ZSBpbiB0aGUgcmVzdWx0IGFsb25nIHdpdGggdGhlIG5hbWUgYW5kIGRldGFpbHMgb2YgdGhlIHBhcmFtZXRlciB0aGF0IGNvbnRhaW5lZCB0aGUgaGFzaGVkIHZhbHVlIGFuZCB0aGUgcGFyYW1ldGVyIHRoYXQgY29udGFpbmVkIHRoZSBjbGVhci10ZXh0IHZhbHVlIHVzZWQgdG8gY3JhY2sgdGhlIGhhc2guDQpBZ2FpbiB0aGUgZmluZGluZ3MgYXJlIGNhdGVnb3JpemVkIGJ5IGhvc3RuYW1lLiBDbGljayBvbiBhIGhvc3RuYW1lIHRvIHNlZSBpZiBpdCBjb250YWluZWQgYW55IGhhc2hlZCBwYXJhbWV0ZXIgdmFsdWVzLg0KDQpQb3RlbnRpYWwgU3RvcmVkIFhTUyBDYW5kaWRhdGVzOg0KPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0NClN0b3JlZCBYU1Mgb25seSBoYXBwZW5zIHdoZW4gdGhlIGFwcGxpY2F0aW9uIHN0b3JlcyB1c2VyIGlucHV0IG9uIHRoZSBzZXJ2ZXItc2lkZSBhbmQgcmV0dXJucyBpdCBiYWNrIGluIHNvbWUgb3RoZXIgcGFydCBvZiB0aGUgc2l0ZS4gSW4gYSBiaWcgYXBwbGljYXRpb24gaXQgd291bGQgYmUgZGlmZmljdWx0IHRvIGZpbmQgb3V0IHRoZSBwb3RlbnRpYWwgYXJlYXMgd2hlcmUgdGhpcyB0eXBlIG9mIHN0b3JlZCByZWZsZWN0aW9uIGJlaGF2aW91ciBpcyBoYXBwZW5pbmcuDQpIQVdBUyBpZGVudGlmaWVzIGFsbCBhcmVhcyB3aGVyZSBwYXJhbWV0ZXIgdmFsdWVzIGZyb20gc2F5IFJlcXVlc3QgQSBhcHBlYXJzIGluIHRoZSBib2R5IG9mIGFuIHVucmVsYXRlZCBSZXNwb25zZSBCLiBJZiBSZXF1ZXN0IEIgZGlkIG5vdCBjb250YWluIHRoZXNlIHBhcmFtZXRlciB2YWx1ZXMgdGhlbiB0aGVyZSBpcyBhIHBvc3NpYmlsaXR5IHRoYXQgdGhpcyB3YXMgcHV0IGluIHRvIFJlc3BvbnNlIEIgYnkgdGhlIHNlcnZlciBhZnRlciBzdG9yaW5nIHRoZW0gZnJvbSBSZXF1ZXN0IEEgb24gdGhlIHNlcnZlci1zaWRlLg0KDQpBbGwgaWRlbnRpZmllZCBpbnN0YW5jZXMgb2YgdGhpcyBiZWhhdmlvdXIgYXJlIGNhdGVnb3JpemVkIGJ5IGhvc3RuYW1lIGFuZCBsaXN0ZWQgaGVyZS4gQ2xpY2sgb24gYSBob3N0bmFtZSB0byBzZWUgaWYgdGhlcmUgd2VyZSBhbnkgc3RvcmVkIHJlZmxlY3Rpb25zLiBTbWFsbCBwYXJhbWV0ZXIgdmFsdWVzIGFyZSBpZ25vcmVkIGR1cmluZyB0aGlzIGFuYWx5c2lzIHRvIHJlZHVjZSBub2lzZS4=')
		result_tabs.TabPages['tab_page_21'].Controls.Add(mod_text_box_21)
		ui.ModControls['mod_text_box_21'] = mod_text_box_21
		ui.Controls.Add(result_tabs)
		ui.ModControls['result_tabs'] = result_tabs
		control_btn = ModButton()
		control_btn.Name = 'control_btn'
		control_btn.Size = ModUiTools.GetSizeDefinition(135,23)
		control_btn.Location = ModUiTools.GetLocationDefinition(12,15)
		control_btn.Anchor = ModUiTools.GetAnchorStyleDefinition(True,False,True,False)
		control_btn.Dock = ModUiTools.GetDockStyleDefinition('None')
		control_btn.Enabled = True
		control_btn.BackColor = ModUiTools.GetColorDefinition(-986896)
		control_btn.ForeColor = ModUiTools.GetColorDefinition(-16777216)
		control_btn.Font = ModUiTools.GetFontDefinition('Microsoft Sans Serif',8.25,False,False,False,False)
		control_btn.Text =  Tools.Base64Decode('U3RhcnQgQW5hbHlzaXM=')
		control_btn.Click += lambda s,e: self.start_stop_hawas()
		ui.Controls.Add(control_btn)
		ui.ModControls['control_btn'] = control_btn
		ui.ShowUi()

		self.ui = ui
		ui.ModControls['show_results_btn'].SetVisible(False)
		self.hide_results()

	def start_stop_hawas(self):
		if self.ui.ModControls['control_btn'].Text == "Start Analysis":
			self.start_hawas()
		else:
			self.stop_hawas()
	
	def start_hawas(self):
		self.hide_results()
		self.log_sources = ["Proxy"]
		self.params = Structures.UniversalParametersList()
		self.encoded_values = Structures.UniversalEncodedValuesList()
		self.hashed_values = Structures.UniversalHashedValuesList()
		self.stored_reflections = Structures.UniversalStoredReflectionsList()
		self.config = HawasConfig.Settings(self)
		try:
			self.log_reader = LogReader.Reader(self)
			self.thread_id = IronThread.Run(self.log_reader.read_logs)
			self.ui.ModControls['control_btn'].SetText("Stop Analysis")
		except Exception as e:
			self.ui.ModControls['status_lbl'].SetText("Could not start analysis - {0}".format(e.message))
	
	def stop_hawas(self):
		self.ui.ModControls['status_lbl'].SetText('Analysis stopped.')
		self.ui.ModControls['control_btn'].SetText("Start Analysis")
		IronThread.Stop(self.thread_id)
		
	def end_hawas(self):
		self.ui.ModControls['control_btn'].SetText("Start Analysis")
		self.ui.ModControls['show_results_btn'].SetVisible(True)
	
	def hide_results(self):
		self.ui.ModControls['result_tabs'].SetVisible(False)
	
	def show_status(self, msg):
		self.ui.ModControls['status_lbl'].SetText(msg)
	
	def show_results(self):
		self.reset_results_ui()
		self.ui.ModControls['result_tabs'].SetVisible(True)
		self.show_hosts()
	
	def show_hosts(self):
		self.ui.ModControls['pnv_hosts_grid'].Rows.Clear()
		for base_url in self.params.get_base_urls():
			self.ui.ModControls['pnv_hosts_grid'].Rows.Add(Tools.ToDotNetArray([base_url]))
		
		self.ui.ModControls['enc_hosts_grid'].Rows.Clear()
		for base_url in self.encoded_values.get_base_urls():
			self.ui.ModControls['enc_hosts_grid'].Rows.Add(Tools.ToDotNetArray([base_url]))
		
		self.ui.ModControls['hashed_hosts_grid'].Rows.Clear()
		for base_url in self.hashed_values.get_base_urls():
			self.ui.ModControls['hashed_hosts_grid'].Rows.Add(Tools.ToDotNetArray([base_url]))
		
		self.ui.ModControls['sr_hosts_grid'].Rows.Clear()
		for base_url in self.stored_reflections.get_base_urls():
			self.ui.ModControls['sr_hosts_grid'].Rows.Add(Tools.ToDotNetArray([base_url]))
	
	def pnv_hosts_grid_clicked(self):
		if len(self.ui.ModControls['pnv_hosts_grid'].SelectedRows) > 0:
			base_url = str(self.ui.ModControls['pnv_hosts_grid'].SelectedRows[0].Cells[0].Value)
			self.ui.ModControls['pnv_selected_host_tb'].SetText(base_url)
			self.selected_base_url = base_url
			self.show_parameter_names()
	
	def show_parameter_names(self):
		self.ui.ModControls['pnv_selected_parameter_tb'].SetText("")
		param_list = self.params.get_parameters_list(self.selected_base_url)
		self.ui.ModControls['pnv_parameters_grid'].Rows.Clear()
		self.ui.ModControls['pnv_parameters_grid'].Rows.Add(Tools.ToDotNetArray([-2, "*Select All Parameters*"]))
		self.ui.ModControls['pnv_parameters_grid'].Rows.Add(Tools.ToDotNetArray([-1, "*Select Url Path Parts*"]))
		for id in param_list.get_ids():
			self.ui.ModControls['pnv_parameters_grid'].Rows.Add(Tools.ToDotNetArray([id, param_list.get_parameter(id).name]))
		self.ui.ModControls['pnv_parameters_grid'].SetVisible(True)
		self.ui.ModControls['pnv_selected_parameter_tb'].SetVisible(True)
		self.reset_pnv_values_ui()
		self.reset_pnv_sections_ui()
	
	def pnv_parameters_grid_clicked(self):
		if len(self.ui.ModControls['pnv_parameters_grid'].SelectedRows) > 0:
			parameter_id = int(self.ui.ModControls['pnv_parameters_grid'].SelectedRows[0].Cells[0].Value)
			parameter_name = str(self.ui.ModControls['pnv_parameters_grid'].SelectedRows[0].Cells[1].Value)
			self.ui.ModControls['pnv_selected_parameter_tb'].SetText(parameter_name)
			self.selected_parameter_id = parameter_id
			self.show_parameter_sections()
	
	def show_parameter_sections(self):
		param_list = self.params.get_parameters_list(self.selected_base_url)
		sections = []
		
		if self.selected_parameter_id > 0:
			param = param_list.get_parameter(self.selected_parameter_id)
			sections.extend(param.sections)
		elif self.selected_parameter_id == -2:
			for pid in param_list.get_ids():
				param = param_list.get_parameter(pid)
				for section in param.sections:
					if sections.count(section) == 0:
						sections.append(section)
						if len(sections) == 8:#all possible sections
							break
		elif self.selected_parameter_id == -1:
			self.selected_section = "Url Path Part"
			self.show_parameter_values()
			self.reset_pnv_sections_ui()
			return
			
		self.ui.ModControls['pnv_sections_grid'].Rows.Clear()
		self.ui.ModControls['pnv_sections_grid'].Rows.Add(Tools.ToDotNetArray(["*Select All Sections*"]))
		for section in sections:
			self.ui.ModControls['pnv_sections_grid'].Rows.Add(Tools.ToDotNetArray([section]))
		self.ui.ModControls['pnv_sections_grid'].SetVisible(True)
		self.reset_pnv_values_ui()
	
	def pnv_sections_grid_clicked(self):
		if len(self.ui.ModControls['pnv_sections_grid'].SelectedRows) > 0:
			section = str(self.ui.ModControls['pnv_sections_grid'].SelectedRows[0].Cells[0].Value)
			self.selected_section = section
			self.show_parameter_values()
	
	def show_parameter_values(self):
		self.ui.ModControls['pnv_selected_value_tb'].SetText("")
		self.ui.ModControls['pnv_selected_value_log_ids_tb'].SetText("")
		values_dict = {}
		param_list = self.params.get_parameters_list(self.selected_base_url)
		sections = []
		param_ids = []
		if self.selected_parameter_id > 0:
			param_ids = [self.selected_parameter_id]
		elif self.selected_parameter_id == -2:
			param_ids.extend(param_list.get_ids())

		for pid in param_ids:
			param = param_list.get_parameter(pid)
			for vid in param.values.get_ids():
				value = param.values.get_value_with_id(vid)
				if value.section == self.selected_section or self.selected_section.startswith("*"):
					if not values_dict.has_key(value.value):
						values_dict[value.value] = []
					values_dict[value.value].extend(value.proxy_log_ids)
		
		self.ui.ModControls['pnv_values_grid'].Rows.Clear()
		for value in values_dict.keys():
			values_dict[value].sort()
			log_ids = str(values_dict[value]).lstrip('[').rstrip(']')
			self.ui.ModControls['pnv_values_grid'].Rows.Add(Tools.ToDotNetArray([value, log_ids]))
		
		self.ui.ModControls['pnv_values_grid'].SetVisible(True)
		self.ui.ModControls['pnv_selected_value_tb'].SetVisible(True)
		self.ui.ModControls['pnv_selected_value_log_ids_tb'].SetVisible(True)
		self.ui.ModControls['select_value_lbl'].SetVisible(True)
		self.ui.ModControls['selected_value_log_ids_lbl'].SetVisible(True)
	
	def pnv_values_grid_clicked(self):
		if len(self.ui.ModControls['pnv_values_grid'].SelectedRows) > 0:
			value = str(self.ui.ModControls['pnv_values_grid'].SelectedRows[0].Cells[0].Value)
			log_ids = str(self.ui.ModControls['pnv_values_grid'].SelectedRows[0].Cells[1].Value)
			self.ui.ModControls['pnv_selected_value_tb'].SetText(value)
			self.ui.ModControls['pnv_selected_value_log_ids_tb'].SetText(log_ids)

	
	def reset_results_ui(self):
		self.reset_pnv_hosts_ui()
		self.reset_pnv_parameter_names_ui()
		self.reset_pnv_sections_ui()
		self.reset_pnv_values_ui()
		
	def reset_pnv_hosts_ui(self):
		self.ui.ModControls['pnv_hosts_grid'].Rows.Clear()
		self.ui.ModControls['pnv_selected_host_tb'].SetText("")
		
	def reset_pnv_parameter_names_ui(self):
		self.ui.ModControls['pnv_parameters_grid'].Rows.Clear()
		self.ui.ModControls['pnv_selected_parameter_tb'].SetText("")
		self.ui.ModControls['pnv_selected_parameter_tb'].SetVisible(False)
		self.ui.ModControls['pnv_parameters_grid'].SetVisible(False)
	
	def reset_pnv_sections_ui(self):
		self.ui.ModControls['pnv_sections_grid'].Rows.Clear()
		self.ui.ModControls['pnv_sections_grid'].SetVisible(False)
	
	def reset_pnv_values_ui(self):
		self.ui.ModControls['pnv_values_grid'].Rows.Clear()
		self.ui.ModControls['pnv_selected_value_tb'].SetText("")
		self.ui.ModControls['pnv_selected_value_log_ids_tb'].SetText("")
		self.ui.ModControls['select_value_lbl'].SetVisible(False)
		self.ui.ModControls['selected_value_log_ids_lbl'].SetVisible(False)
		self.ui.ModControls['pnv_values_grid'].SetVisible(False)
		self.ui.ModControls['pnv_selected_value_tb'].SetVisible(False)
		self.ui.ModControls['pnv_selected_value_log_ids_tb'].SetVisible(False)
	
	def enc_hosts_grid_click(self):
		if len(self.ui.ModControls['enc_hosts_grid'].SelectedRows) > 0:
			base_url = str(self.ui.ModControls['enc_hosts_grid'].SelectedRows[0].Cells[0].Value)
			self.ui.ModControls['enc_selected_host_tb'].SetText(base_url)
			self.show_enc_values(base_url)
			
	def show_enc_values(self, base_url):
		self.reset_enc_values_ui()
		enc_list = self.encoded_values.get_list(base_url)
		for v_id in enc_list.get_ids():
			enc_val = enc_list.get(v_id)
			log_ids = str(enc_val.log_ids).lstrip('[').rstrip(']')
			parameter_names = str(enc_val.parameter_names).lstrip('[').rstrip(']')
			if len(enc_val.base64_decoded_value) > 0:
				self.ui.ModControls['enc_values_grid'].Rows.Add(Tools.ToDotNetArray([enc_val.value, "Base64", enc_val.base64_decoded_value, log_ids, parameter_names]))
			if len(enc_val.hex_decoded_value) > 0:
				self.ui.ModControls['enc_values_grid'].Rows.Add(Tools.ToDotNetArray([enc_val.value, "Hex", enc_val.hex_decoded_value, log_ids, parameter_names]))
	
	def enc_values_grid_click(self):
		if len(self.ui.ModControls['enc_values_grid'].SelectedRows) > 0:
			value = str(self.ui.ModControls['enc_values_grid'].SelectedRows[0].Cells[0].Value)
			decoded_value = str(self.ui.ModControls['enc_values_grid'].SelectedRows[0].Cells[2].Value)
			log_ids = str(self.ui.ModControls['enc_values_grid'].SelectedRows[0].Cells[3].Value)
			parameter_names = str(self.ui.ModControls['enc_values_grid'].SelectedRows[0].Cells[4].Value)
			
			self.ui.ModControls['enc_original_value_tb'].SetText(value)
			self.ui.ModControls['enc_decoded_value_tb'].SetText(decoded_value)
			self.ui.ModControls['enc_log_ids_tb'].SetText(log_ids)
			self.ui.ModControls['enc_parameter_names_tb'].SetText(parameter_names)

	def reset_enc_ui(self):
		self.ui.ModControls['enc_hosts_grid'].Rows.Clear()
		self.ui.ModControls['enc_selected_host_tb'].SetText("")
		self.reset_enc_values_ui()
	
	def reset_enc_values_ui(self):
		self.ui.ModControls['enc_values_grid'].Rows.Clear()
		self.ui.ModControls['enc_original_value_tb'].SetText("")
		self.ui.ModControls['enc_decoded_value_tb'].SetText("")
		self.ui.ModControls['enc_log_ids_tb'].SetText("")
		self.ui.ModControls['enc_parameter_names_tb'].SetText("")
		
	def hashed_hosts_grid_click(self):
		if len(self.ui.ModControls['hashed_hosts_grid'].SelectedRows) > 0:
			base_url = str(self.ui.ModControls['hashed_hosts_grid'].SelectedRows[0].Cells[0].Value)
			self.ui.ModControls['hashed_selected_host_tb'].SetText(base_url)
			self.show_hashed_values(base_url)
			
	def show_hashed_values(self, base_url):
		self.reset_hashed_values_ui()
		hashed_list = self.hashed_values.get_list(base_url)
		for v_id in hashed_list.get_ids():
			hashed_val = hashed_list.get(v_id)
			log_ids = str(hashed_val.log_ids).lstrip('[').rstrip(']')
			parameter_names = str(hashed_val.parameter_names).lstrip('[').rstrip(']')
			self.ui.ModControls['hashed_values_grid'].Rows.Add(Tools.ToDotNetArray([hashed_val.value, hashed_val.hash_type, hashed_val.cracked_value, log_ids, parameter_names]))
	
	def hashed_values_grid_click(self):
		if len(self.ui.ModControls['hashed_values_grid'].SelectedRows) > 0:
			value = str(self.ui.ModControls['hashed_values_grid'].SelectedRows[0].Cells[0].Value)
			cracked_value = str(self.ui.ModControls['hashed_values_grid'].SelectedRows[0].Cells[2].Value)
			log_ids = str(self.ui.ModControls['hashed_values_grid'].SelectedRows[0].Cells[3].Value)
			parameter_names = str(self.ui.ModControls['hashed_values_grid'].SelectedRows[0].Cells[4].Value)
			
			self.ui.ModControls['hashed_original_value_tb'].SetText(value)
			self.ui.ModControls['hashed_cracked_value_tb'].SetText(cracked_value)
			self.ui.ModControls['hashed_log_ids_tb'].SetText(log_ids)
			self.ui.ModControls['hashed_parameter_names_tb'].SetText(parameter_names)
	
	def reset_hashed_ui(self):
		self.ui.ModControls['hashed_hosts_grid'].Rows.Clear()
		self.ui.ModControls['hashed_selected_host_tb'].SetText("")
		self.reset_hashed_values_ui()
	
	def reset_hashed_values_ui(self):
		self.ui.ModControls['hashed_values_grid'].Rows.Clear()
		self.ui.ModControls['hashed_original_value_tb'].SetText("")
		self.ui.ModControls['hashed_cracked_value_tb'].SetText("")
		self.ui.ModControls['hashed_log_ids_tb'].SetText("")
		self.ui.ModControls['hashed_parameter_names_tb'].SetText("")
	
	def sr_hosts_grid_click(self):
		if len(self.ui.ModControls['sr_hosts_grid'].SelectedRows) > 0:
			base_url = str(self.ui.ModControls['sr_hosts_grid'].SelectedRows[0].Cells[0].Value)
			self.ui.ModControls['sr_selected_host_tb'].SetText(base_url)
			self.show_sr_values(base_url)
			
	def show_sr_values(self, base_url):
		self.reset_sr_values_ui()
		sr_list = self.stored_reflections.get_list(base_url)
		for i_id in sr_list.get_ids():
			sr_item = sr_list.get(i_id)
			req_log_ids = str(sr_item.request_log_ids).lstrip('[').rstrip(']')
			res_log_ids = str(sr_item.response_log_ids).lstrip('[').rstrip(']')
			self.ui.ModControls['sr_values_grid'].Rows.Add(Tools.ToDotNetArray([sr_item.parameter_name, sr_item.value, req_log_ids, res_log_ids]))
	
	def sr_values_grid_click(self):
		if len(self.ui.ModControls['sr_values_grid'].SelectedRows) > 0:
			parameter_name = str(self.ui.ModControls['sr_values_grid'].SelectedRows[0].Cells[0].Value)
			value = str(self.ui.ModControls['sr_values_grid'].SelectedRows[0].Cells[1].Value)
			req_log_ids = str(self.ui.ModControls['sr_values_grid'].SelectedRows[0].Cells[2].Value)
			res_log_ids = str(self.ui.ModControls['sr_values_grid'].SelectedRows[0].Cells[3].Value)
			
			self.ui.ModControls['sr_parameter_name_tb'].SetText(parameter_name)
			self.ui.ModControls['sr_value_tb'].SetText(value)
			self.ui.ModControls['sr_request_log_ids_tb'].SetText(req_log_ids)
			self.ui.ModControls['sr_response_log_ids_tb'].SetText(res_log_ids)
	
	def reset_sr_ui(self):
		self.ui.ModControls['sr_hosts_grid'].Rows.Clear()
		self.ui.ModControls['sr_selected_host_tb'].SetText("")
		self.reset_sr_values_ui()
	
	def reset_sr_values_ui(self):
		self.ui.ModControls['sr_values_grid'].Rows.Clear()
		self.ui.ModControls['sr_parameter_name_tb'].SetText("")
		self.ui.ModControls['sr_value_tb'].SetText("")
		self.ui.ModControls['sr_request_log_ids_tb'].SetText("")
		self.ui.ModControls['sr_response_log_ids_tb'].SetText("")
	
	def start_bruteforce(self, r):
		dictionary_items = ['admin', 'backup', 'db', 'bank']
		self.ui.ModControls['out_tb'].AddText('Starting directory guessing....\r\n')
		try:
			for item in dictionary_items:
				rr = r.GetClone()
				url = '/' + item + '/'
				rr.Url = url
				res = rr.Send()
				if res.Code == 200 or res.Code == 403:
					self.ui.ModControls['out_tb'].AddText('Found URL - {0}\r\n'.format(url))
			self.ui.ModControls['out_tb'].AddText('Directory guessing complete.')
		except Exception as e:
			if e.clsException.GetType().Name != "ThreadAbortException":
				self.ui.ModControls['out_tb'].SetText('Directory Guessing stopped with error - {0}'.format(e.message))
		self.ui.ModControls['start_btn'].SetText("Start")
	
m = HAWAS()
Module.Add(m.GetInstance())
