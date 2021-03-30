# -*- coding: utf-8 -*-
""" http based est protocol handler """
from http.server import BaseHTTPRequestHandler
# pylint: disable=E0401
from est_proxy.helper import config_load, logger_setup, b64_encode
from est_proxy.version import __version__

class ESTSrvHandler(BaseHTTPRequestHandler):
    """ serverside of est protocol handler """
    protocol_version = "HTTP/1.1"
    server_version = 'est_proxy'
    sys_version = __version__
    logger = None
    cfg_file = None

    def __init__(self, *args, **kwargs):
        # self.cfg_file = args[2].__dict__['cfg_file'])
        # self._config_load()
        # initialize logger
        self.logger = args[2].__dict__['logger']
        # Instantiate the superclass
        super().__init__(*args, **kwargs)

    def _cacerts_get(self):
        """ get ca certificates """
        self.logger.debug('ESTSrvHandler._cacerts_get()')
        ca_p7b = open('ca_bundle.p7b','r', encoding='utf8').read()
        # print(ca_p7b)
        # 64enc = b64_encode(self.logger, ca_p7b)
        b64enc = ca_p7b
        return b64enc

    def _config_load(self):
        """ load config from file """
        config_dic = config_load(cfg_file=self.cfg_file)
        debug = config_dic.getboolean('DEFAULT', 'debug', fallback=False)
        self.logger = logger_setup(debug, cfg_file=self.cfg_file)

    def _set_response(self, code=404, content_type='text/html', clength=200):
        """ set response method """
        self.send_response( code )
        self.send_header('Status', '200 OK')
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Transfer-Encoding', 'base64')
        self.send_header('Content-Length', clength)
        self.end_headers()

    # pylint: disable=C0103
    def do_GET(self):
        """ this is a http get """
        self.logger.debug('ESTSrvHandler.do_GET %s path: %s', self.client_address, self.path)
        content = None
        if self.path == '/.well-known/est/cacerts':
            code = 200
            ca_certs = self._cacerts_get()
            if ca_certs:
                code = 200
                content_type = 'application/pkcs7-mime'
                content = ca_certs
            else:
                code = 500
                content_type = 'text/html'
        else:
            code = 404
            content_type = 'text/html'

        content_length = len(str(content))
        content = content.encode('utf8')
        self._set_response(code, content_type, content_length)
        # self.wfile.write("GET request for {}".format(self.path).encode('utf-8'))
        self.wfile.write(content)

    def do_POST(self):
        """ this is a http post """
        self.logger.debug('ESTSrvHandler.do_POST %s path: %s', self.client_address, self.path)
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        self.logger.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n", str(self.path), str(self.headers), post_data.decode('utf-8'))

        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))
