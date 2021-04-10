# -*- coding: utf-8 -*-
""" http based est protocol handler """
import os
import tempfile
import subprocess
import importlib
from http.server import BaseHTTPRequestHandler
# pylint: disable=E0401
from est_proxy.helper import config_load, ca_handler_get, logger_setup
from est_proxy.version import __version__

class ESTSrvHandler(BaseHTTPRequestHandler):
    """ serverside of est protocol handler """
    cahandler = None
    debug = False
    cfg_file = None
    logger = None
    openssl_bin = None
    protocol_version = "HTTP/1.1"
    server_version = 'est_proxy'
    sys_version = __version__

    def __init__(self, *args, **kwargs):
        """ init function """
        # get config and logger file
        try:
            self.cfg_file = args[2].__dict__['cfg_file']
        except BaseException:
            # self.logger.error('ESTSrvHandler.__init__ cfg_file load from args failed')
            self.cfg_file = 'acme_proxy.cfg'
        try:
            self.logger = args[2].__dict__['logger']
        except BaseException:
            self.logger = logger_setup(self.debug, cfg_file=self.cfg_file)
        if not self.openssl_bin:
            self._config_load()
        try:
            # Instantiate the superclass
            super().__init__(*args, **kwargs)
        except BaseException as err_:
            self.logger.error('ESTSrvHandler.__init__ superclass init failed: {0}'.format(err_))

    def _cacerts_get(self):
        """ get ca certificates """
        self.logger.debug('ESTSrvHandler._cacerts_get()')
        with self.cahandler(self.cfg_file, self.logger) as ca_handler:
            # get ca_certs
            ca_certs = ca_handler.ca_certs_get()
            # convert pem to pkcs#7
            if ca_certs:
                ca_pkcs7 = self._pkcs7_convert(ca_certs)
            else:
                ca_pkcs7 = None
        self.logger.debug('ESTSrvHandler._cacerts_get() ended with: {0}'.format(bool(ca_pkcs7)))
        return ca_pkcs7

    def _cacerts_split(self, ca_certs):
        """ split ca_certs """
        self.logger.debug('ESTSrvHandler._cacerts_split()')
        ca_certs_list = []
        if ca_certs:
            cert = ""
            for line in ca_certs.splitlines(True):
                cert += line
                if '-----END CERTIFICATE-----' in line:
                    ca_certs_list.append(cert)
                    cert = ""
        self.logger.debug('ESTSrvHandler._cacerts_split() ended with: {0} certs'.format(len(ca_certs_list)))
        return ca_certs_list

    def _cacerts_dump(self, ca_list):
        """ dump certs to file """
        self.logger.debug('ESTSrvHandler._cacerts_dump()')
        ca_file_names = []
        if isinstance(ca_list, list):
            for cert in ca_list:
                fso = tempfile.NamedTemporaryFile(mode='w+', delete=False)
                fso.write(cert)
                fso.close()
                ca_file_names.append(fso.name)
        self.logger.debug('ESTSrvHandler._cacerts_dump() ended with: {0} certs'.format(len(ca_file_names)))
        return ca_file_names

    def _cert_enroll(self, csr):
        """ enroll cert """
        self.logger.debug('ESTSrvHandler._cert_enroll()')
        with self.cahandler(self.cfg_file, self.logger) as ca_handler:
            # get ca_certs
            (error, cert) = ca_handler.enroll(csr)
            if not error and cert:
                cert_pkcs7 = self._pkcs7_convert(cert, pkcs7_clean=True)

        self.logger.debug('ESTSrvHandler._cacerts_get() ended with: {0}'.format(bool(cert_pkcs7)))
        return (error, cert_pkcs7)

    def _config_load(self):
        """ load config from file """
        self.logger.debug('ESTSrvHandler._config_load()')
        config_dic = config_load(self.logger, cfg_file=self.cfg_file)

        if 'DEFAULT' in config_dic and 'openssl_bin' in config_dic['DEFAULT']:
            self.openssl_bin = config_dic['DEFAULT']['openssl_bin']
        else:
            self.openssl_bin = 'openssl'

        if 'CAhandler' in config_dic and 'handler_file' in config_dic['CAhandler']:
            try:
                ca_handler_module = importlib.import_module(ca_handler_get(self.logger, config_dic['CAhandler']['handler_file']))
            except BaseException:
                self.logger.error('ESTSrvHandler._config_load(): CAhandler {0} could not get loaded. Loading default hander...'.format(config_dic['CAhandler']['handler_file']))
                try:
                    ca_handler_module = importlib.import_module('est_proxy.ca_handler')
                except BaseException:
                    self.logger.error('ESTSrvHandler._config_load():  Loading default hander failed.')
                    ca_handler_module = None
        else:
            if 'CAhandler' in config_dic:
                try:
                    ca_handler_module = importlib.import_module('est_proxy.ca_handler')
                except BaseException as err_:
                    self.logger.error('ESTSrvHandler._config_load(): default CAhandler could not get loaded. err: {0}'.format(err_))
                    ca_handler_module = None
            else:
                self.logger.error('ESTSrvHandler._config_load(): CAhandler configuration missing in config file')
                ca_handler_module = None

        if ca_handler_module:
            # store handler in variable
            self.cahandler = ca_handler_module.CAhandler

        self.logger.debug('ca_handler: {0}'.format(ca_handler_module))
        self.logger.debug('ESTSrvHandler._config_load() ended')

    def _pkcs7_clean(self, pkcs7_struc):
        """ remove cert header and footer """
        self.logger.debug('ESTSrvHandler._pkcs7_clean()')
        if isinstance(pkcs7_struc, bytes):
            pkcs7_struc = pkcs7_struc.decode('utf-8')
        if pkcs7_struc and isinstance(pkcs7_struc, str):
            # remove pkcs7 start end end tags
            pkcs7_struc = pkcs7_struc.replace('-----END PKCS7-----', '')
            pkcs7_struc = pkcs7_struc.replace('-----BEGIN PKCS7-----', '')
            pkcs7_struc = "\n".join([s for s in pkcs7_struc.split("\n") if s])
        return pkcs7_struc

    def _pkcs7_convert(self, ca_certs, pkcs7_clean=False):
        """ convert to pkcs#7 """
        self.logger.debug('ESTSrvHandler._pkcs7_convert()')

        pkcs7_struc = None

        if ca_certs:
            # split pem-chain into certs
            ca_list = self._cacerts_split(ca_certs)
            # dump certs into temporary files
            file_names = self._cacerts_dump(ca_list)

            if self.openssl_bin and file_names:
                fso = tempfile.NamedTemporaryFile(mode='w+', delete=False)
                pkcs7_file = fso.name
                fso.close()
                # create command-line to convert
                openssl_cmd = self._opensslcmd_build(file_names, pkcs7_file)
                # run command and capture return code
                rcode = subprocess.call(openssl_cmd)
                if rcode == 0:
                    with open(pkcs7_file, 'r', encoding='utf-8') as fso:
                        pkcs7_struc = fso.read()

                if pkcs7_struc and pkcs7_clean:
                    pkcs7_struc = self._pkcs7_clean(pkcs7_struc)

                # add outfile to list and delete all files
                file_names.append(pkcs7_file)
                self._tmpfiles_clean(file_names)

        return pkcs7_struc

    def _tmpfiles_clean(self, file_name_list):
        """ clean files """
        self.logger.debug('ESTSrvHandler._tmpfiles_clean()')
        for file_name in file_name_list:
            try:
                os.remove(file_name)
            except BaseException as err:
                print(file_name, err)

    def _opensslcmd_build(self, file_name_list, pkcs7_file):
        """ build ssl cmd """
        # convert to list if string or byte
        if isinstance(file_name_list, str):
            file_name_list = [file_name_list]
        elif isinstance(file_name_list, bytes):
            file_name_list = [file_name_list.decode('utf-8')]
        # create list of openssl parameters
        cmd_list = [self.openssl_bin, 'crl2pkcs7', '-nocrl', '-out', pkcs7_file]
        for file_name in file_name_list:
            cmd_list.extend(['--certfile', file_name])
        return cmd_list

    def _set_response(self, code=404, content_type='text/html', clength=0, encoding=None):
        """ set response method """
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        if encoding:
            self.send_header('Content-Transfer-Encoding', encoding)
        if clength:
            self.send_header('Content-Length', clength)
        self.send_header('Connection', 'close')
        self.end_headers()

    def get_process(self):
        """ main method to process get requests """
        self.logger.debug('ESTSrvHandler.get_process %s', self.path)
        content = None
        content_length = 0
        encoding = None

        if self.path == '/.well-known/est/cacerts':
            code = 200
            ca_certs = self._cacerts_get()
            if ca_certs:
                code = 200
                content_type = 'application/pkcs7-mime'
                content = ca_certs
                encoding = 'base64'
            else:
                code = 500
                content_type = 'text/html'
        else:
            code = 400
            content_type = 'text/html'
            content = 'An unknown error has occured.'

        if content:
            content_length = len(str(content))
            content = content.encode('utf8')

        return(code, content_type, content_length, encoding, content)

    def post_process(self, data):
        """ main method to process post requests """
        self.logger.debug('ESTSrvHandler.get_process %s', self.path)
        content = None
        content_length = 0
        encoding = None
        code = 400

        if self.path == '/.well-known/est/simpleenroll' or self.path == '/.well-known/est/simplereenroll':
            # enroll certificate
            (error, cert) = self._cert_enroll(data)
            if not error:
                code = 200
                content_type = 'application/pkcs7-mime; smime-type=certs-only'
                content = cert
                encoding = 'base64'
            else:
                code = 500
        else:
            code = 400
            content_type = 'text/html'
            content = 'An unknown error has occured.'

        if content:
            content_length = len(str(content))
            content = content.encode('utf8')

        return(code, content_type, content_length, encoding, content)

    # pylint: disable=C0103
    def do_GET(self):
        """ this is a http get """
        self.logger.debug('ESTSrvHandler.do_GET %s path: %s', self.client_address, self.path)
        # process request
        (code, content_type, content_length, encoding, content) = self.get_process()
        # write response
        self._set_response(code, content_type, content_length, encoding)
        if content:
            self.wfile.write(content)

    def do_POST(self):
        """ this is a http post """
        self.logger.debug('ESTSrvHandler.do_POST %s path: %s', self.client_address, self.path)
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself

        # self.logger.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n", str(self.path), str(self.headers), post_data.decode('utf-8'))
        # process requests
        (code, content_type, content_length, encoding, content) = self.post_process(post_data)

        # write response
        self._set_response(code, content_type, content_length, encoding)
        if content:
            self.wfile.write(content)

        #self._set_response()
        #self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))
