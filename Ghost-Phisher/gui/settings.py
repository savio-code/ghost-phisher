import os

cwd = os.getcwd()

def create_settings(object_name,value):                                  #Function for writing last program settings to the settings file
    ''' This function reads the settings file for already
        existing variables, and if they are any conflicting
        variable, it removes it and replaces it
        with the new
    '''
    string = ''
    if value != '':
        last_settings = open(cwd + '/last-ghost-setting.dat','r')
        file_read = last_settings.read()
        last_settings.close()
        os.remove(cwd + '/last-ghost-setting.dat')
        all_files = file_read.splitlines()
        for iterate in all_files:
            if object_name in iterate:
                string += iterate
                old_settings_number = all_files.index(string)
                all_files.pop(old_settings_number)
        all_files.append('%s = %s'%(object_name,value))
        file_input_settings = open(cwd + '/last-ghost-setting.dat','a+')
        for settings in all_files:
            file_input_settings.write('%s\n'%(settings))
        file_input_settings.close()




def read_last_settings(object_name):                                    # Reads object name from settings file and return its value
    ''' This function reads the settings for
        variable assignments and then
        returns the corresponding value
    '''
    target_variable = ''
    settings_file = open(cwd + '/last-ghost-setting.dat','r')
    settings_file_process = settings_file.read()
    settings_file_process2 = settings_file_process.splitlines()
    for iterate in settings_file_process2:
        if object_name in iterate:
            target_variable += iterate
    return str(target_variable.split()[2])
