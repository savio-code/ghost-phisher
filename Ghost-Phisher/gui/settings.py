import os
import sqlite3


class Ghost_settings(object):
    def __init__(self):
        self.cwd = os.getcwd()
        self._create_settings_directory()
        self.settings_file = self.cwd + os.sep + "Settings" + os.sep + "ghost_settings.db"
        self.settings_object = sqlite3.connect(self.settings_file)
        self.cursor_object = self.settings_object.cursor()
        self.create_table()


    def _create_settings_directory(self):
        if not os.path.exists(self.cwd + os.sep + "Settings"):
            os.mkdir(self.cwd + os.sep + "Settings")


    def create_table(self):
        self.cursor_object.execute("create table if not exists settings (object text,value text)")
        self.settings_object.commit()


    def create_settings(self,object_name,value):
        ''' This function reads the settings file for already
            existing variables, and if they are any conflicting
            variable, it removes it and replaces it
            with the new
        '''
        if self.setting_exists(object_name):
            self.cursor_object.execute("update settings set value = '%s' where object = '%s'" % (value,object_name))
        else:
            self.cursor_object.execute("insert into settings values ('%s','%s')" % (object_name,value))
        self.settings_object.commit()


    def setting_exists(self,object_name):
        '''This function checks to see if queried
            settings exists in shelve object
        '''
        self.cursor_object.execute("select value from settings where object = '%s'"%(object_name))
        fetch_value = self.cursor_object.fetchall()
        if(len(fetch_value) >= 1):
            return(True)
        return(False)


    def read_last_settings(self,object_name):
        ''' This function reads the settings for
            variable assignments and then
            returns the corresponding value
        '''
        self.cursor_object.execute("select value from settings where object = '%s'"%(object_name))
        fetch_value = self.cursor_object.fetchall()[0][0]
        return(fetch_value)



    def close_setting_file(self):
        '''Function closes write/Read operations
            to settings file
        '''
        self.cursor_object.close()





