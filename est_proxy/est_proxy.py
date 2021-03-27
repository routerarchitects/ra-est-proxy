#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
from tlslite.api import *
from tlslite.constants import CipherSuite, HashAlgorithm, SignatureAlgorithm, GroupName, SignatureScheme
from tlslite.handshakesettings import Keypair, VirtualHost
from tlslite import __version__
from tlslite.utils.compat import b2a_hex, a2b_hex, time_stamp
from tlslite.utils.dns_utils import is_valid_hostname
from tlslite.utils.cryptomath import getRandomBytes
from tlslite.constants import KeyUpdateMessageType
from tlslite import TLSSocketServerMixIn
from socketserver import *
import struct
from helper import config_load, logger_setup, hssrv_options_get, printgoodconnection

try:
    from tack.structures.Tack import Tack

except ImportError:
    pass

def _config_load(debug=None):
    """ load config from file """
    config_dic = config_load(debug)

    debug = config_dic.getboolean('DEFAULT', 'debug', fallback=False)

    arg_dic = {}
    if 'ClientAuth' in config_dic:
        arg_dic['ClientAuth'] = {}
        arg_dic['ClientAuth']['address'] = config_dic.get('ClientAuth', 'address', fallback=None)
        arg_dic['ClientAuth']['port'] = int(config_dic.get('ClientAuth', 'port', fallback='1443'))

        # load key
        key_file = open(config_dic.get('ClientAuth', 'key_file', fallback=None), 'rb').read()
        key_file = str(key_file, 'utf-8')
        arg_dic['ClientAuth']['key_file'] = parsePEMKey(key_file, private=True, implementations=["python"])

        # load cert
        cert_file = open(config_dic.get('ClientAuth', 'cert_file', fallback=None), 'rb').read()
        cert_file = str(cert_file, 'utf-8')
        cert_chain = X509CertChain()
        cert_chain.parsePemList(cert_file)
        arg_dic['ClientAuth']['cert_file'] = cert_chain

    return(debug, arg_dic)


class MyHTTPServer(ThreadingMixIn, TLSSocketServerMixIn, HTTPServer):

    def handshake(self, connection):
        (debug, config_dic) = _config_load()
        logger = logger_setup(debug)
        logger.debug('MyHTTPServer.handshake()')

        hs_options = hssrv_options_get(logger, 'ClientAuth', config_dic)
        request_pha = False
        require_pha = True

        try:
            start = time_stamp()
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 5))
            connection.client_cert_required = require_pha
            # connection.handshakeServer(**hs_options)
            connection.handshakeServer(certChain=config_dic['ClientAuth']['cert_file'], privateKey=config_dic['ClientAuth']['key_file'], reqCert=True)
            try:
                if request_pha:
                    for i in connection.request_post_handshake_auth():
                        pass
            except ValueError as err_:
                # if we can't do PHA, we can't do it
                logger.debug(err_)
                pass

            stop = time_stamp()
        except TLSRemoteAlert as a:
            if a.description == AlertDescription.user_canceled:
                logger.error(str(a))
                return False
            else:
                logger.error('TLSRemoteAlert: {0}'.format(str(a)))
                return False

        except TLSLocalAlert as a:
            if a.description == AlertDescription.handshake_failure:
                print("Unable to negotiate mutually acceptable parameters")
                return False
            else:
                logger.error(str(a))
                raise

        connection.ignoreAbruptClose = True
        print(connection.session.clientCertChain)
        # printgoodconnection(connection, stop-start)
        return True

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\n", str(self.path))
        self._set_response()
        self.wfile.write("GET request for {}".format(self.path).encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                str(self.path), str(self.headers), post_data.decode('utf-8'))

        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))

def srv_run(logger, server_class=MyHTTPServer, handler_class=S, address='127.0.0.1', port=8080):
    logger.debug('srv_run({0})'.format(port))

    server_address = (address, port)
    httpd = server_class(server_address, handler_class)
    logger.info('starting est_proxy on {0}:{1}'.format(address, port))

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':

    # set debug mode
    (DEBUG, CONFIG_DIC) = _config_load()
    LOGGER = logger_setup(DEBUG)

    if 'ClientAuth' in CONFIG_DIC:
        srv_run(logger=LOGGER, address=CONFIG_DIC['ClientAuth']['address'], port=CONFIG_DIC['ClientAuth']['port'])
