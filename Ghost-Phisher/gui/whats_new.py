import settings
import whats_new_ui

from core import update
from PyQt4 import QtGui,QtCore

whats_new_html = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Untitled Document</title>
<style type="text/css">
.Bigger {
	font-size: 18px;
	font-weight: bold;
}
.smaller {
	font-size: 9px;
}
.smaller {
	font-size: 14px;
}
</style></head>


<body>
<p class="Bigger"><strong>Whats New in Ghost Phisher %s</strong></p>
<p class="smaller">* Bug Fixes (Fake AP and Ghost DHCP Server)</p>
</body>
</html>
"""



class whats_new_window(QtGui.QDialog,whats_new_ui.Ui_Dialog):
    def __init__(self):
        QtGui.QDialog.__init__(self)

        self.setupUi(self)
        self.retranslateUi(self)

        self.update_value = update.update_class()
        self.connect(self.whats_new_check,QtCore.SIGNAL("clicked()"),self.disable_check)
        self.webView.setHtml(self.get_Update_Html())


    def disable_check(self):
        self.settings_object = settings.Ghost_settings()
        if(self.whats_new_check.isChecked()):
            self.settings_object.create_settings("disable whats new window","False")
        else:
            self.settings_object.create_settings("disable whats new window","True")
        self.settings_object.close_setting_file()


    def get_Update_Html(self):
        html = whats_new_html % (str(self.update_value.current_version))
        return(html)

