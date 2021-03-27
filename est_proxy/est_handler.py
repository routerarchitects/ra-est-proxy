# -*- coding: utf-8 -*-
""" http based est protocol handler """
from http.server import BaseHTTPRequestHandler
# pylint: disable=E0401
from est_proxy.helper import config_load, logger_setup

class ESTSrvHandler(BaseHTTPRequestHandler):
    """ serverside of est protocol handler """
    logger = None

    def __init__(self, *args, **kwargs):
        self._config_load()
        # Instantiate the superclass
        super().__init__(*args, **kwargs)

    def _config_load(self):
        """ load config from file """
        config_dic = config_load()
        debug = config_dic.getboolean('DEFAULT', 'debug', fallback=False)
        self.logger = logger_setup(debug)

    def _set_response(self):
        """ set response method """
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    # pylint: disable=C0103
    def do_GET(self):
        """ this is a http get """
        self.logger.debug('ESTSrvHandler.do_GET %s path: %s', self.client_address, self.path)
        self._set_response()
        self.wfile.write("GET request for {}".format(self.path).encode('utf-8'))

    def do_POST(self):
        """ this is a http post """
        self.logger.debug('ESTSrvHandler.do_POST %s path: %s', self.client_address, self.path)
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        self.logger.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n", str(self.path), str(self.headers), post_data.decode('utf-8'))

        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))
