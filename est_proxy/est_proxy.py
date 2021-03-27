#!/usr/bin/env python3
""" start script for est_proxy """
from helper import config_load, logger_setup
from est_handler import ESTSrvHandler
from secureserver import SecureServer

def _config_load(debug=None):
    """ load config from file """
    config_dic = config_load(debug)
    debug = config_dic.getboolean('DEFAULT', 'debug', fallback=False)
    svc_dic = {}
    if 'ClientAuth' in config_dic:
        svc_dic['ClientAuth'] = {}
        svc_dic['ClientAuth']['address'] = config_dic.get('ClientAuth', 'address', fallback=None)
        svc_dic['ClientAuth']['port'] = int(config_dic.get('ClientAuth', 'port', fallback='1443'))

    return(debug, svc_dic)

def srv_run(logger, server_class=SecureServer, handler_class=ESTSrvHandler, address='127.0.0.1', port=8080):
    """ function to start server """
    logger.debug('srv_run({0})'.format(port))

    server_address = (address, port)
    httpd = server_class(server_address, handler_class)
    logger.info('starting est_proxy on {0}:{1}'.format(address, port))

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logger.info('stopping est_proxy on {0}:{1}'.format(address, port))

if __name__ == '__main__':

    # set debug mode
    (DEBUG, SVC_DIC) = _config_load()
    LOGGER = logger_setup(DEBUG)

    if 'ClientAuth' in SVC_DIC:
        # start est service supporting  ClientAuth
        srv_run(logger=LOGGER, address=SVC_DIC['ClientAuth']['address'], port=SVC_DIC['ClientAuth']['port'])
