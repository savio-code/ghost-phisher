import os
import shelve


class Ghost_settings(object):
    def __init__(self):
        self.cwd = os.getcwd()
        self._create_settings_directory()
        self.settings_file = self.cwd + os.sep + "Settings" + os.sep + "ghost_settings"
        self.settings_object = shelve.open(self.settings_file)


    def _create_settings_directory(self):
        if not os.path.exists(self.cwd + os.sep + "Settings"):
            os.mkdir(self.cwd + os.sep + "Settings")


    def create_settings(self,object_name,value):
        ''' This function reads the settings file for already
            existing variables, and if they are any conflicting
            variable, it removes it and replaces it
            with the new
        '''
        self.settings_object[object_name] = value


    def setting_exists(self,object_name):
        '''This function checks to see if queried
            settings exists in shelve object
        '''
        try:
            self.settings_object[object_name]
            return(True)
        except(KeyError):
            return(False)


    def read_last_settings(self,object_name):
        ''' This function reads the settings for
            variable assignments and then
            returns the corresponding value
        '''
        settings_string = str(self.settings_object[object_name])
        return(settings_string)



    def close_setting_file(self):
        '''Function closes write/Read operations
            to settings file
        '''
        self.settings_object.close()





