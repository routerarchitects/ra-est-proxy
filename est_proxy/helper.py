#!/usr/bin/python
# -*- coding: utf-8 -*-
""" helper functions for est_srv """
from __future__ import print_function
import os
import logging
import configparser
import base64
from tlslite import SessionCache, HandshakeSettings
from tlslite.constants import CipherSuite, HashAlgorithm, SignatureAlgorithm, GroupName, SignatureScheme

def b64decode_pad(logger, string):
    """ b64 decoding and padding of missing "=" """
    logger.debug('b64decode_pad()')
    try:
        b64dec = base64.urlsafe_b64decode(string + '=' * (4 - len(string) % 4))
    except BaseException:
        b64dec = b'ERR: b64 decoding error'
    return b64dec.decode('utf-8')

def b64_decode(logger, string):
    """ b64 decoding """
    logger.debug('b64decode()')
    return convert_byte_to_string(base64.b64decode(string))
    #if sys.version_info[0] >= 3:
    #    return base64.b64decode(string).decode()
    #else:
    #    return base64.b64decode(string)

def b64_encode(logger, string):
    """ encode a bytestream in base64 """
    logger.debug('b64_encode()')
    return base64.b64encode(convert_string_to_byte(string))

def b64_url_encode(logger, string):
    """ encode a bytestream in base64 url and remove padding """
    logger.debug('b64_url_encode()')
    string = convert_string_to_byte(string)
    encoded = base64.urlsafe_b64encode(string)
    return encoded.rstrip(b"=")

def b64_url_recode(logger, string):
    """ recode base64_url to base64 """
    logger.debug('b64_url_recode()')
    padding_factor = (4 - len(string) % 4) % 4
    string = convert_byte_to_string(string)
    string += "="*padding_factor
    # differ between py2 and py3
    # pylint: disable=E0602
    if sys.version_info[0] >= 3:
        result = str(string).translate(dict(zip(map(ord, u'-_'), u'+/')))
    else:
        result = unicode(string).translate(dict(zip(map(ord, u'-_'), u'+/')))

def config_load(logger=None, mfilter=None, cfg_file=os.path.dirname(__file__)+'/'+'est_proxy.cfg'):
    """ small configparser wrappter to load a config file """
    if logger:
        logger.debug('load_config({1}:{0})'.format(mfilter, cfg_file))
    config = configparser.RawConfigParser()
    config.optionxform = str
    config.read(cfg_file)

    return config

def connection_log(logger, connection, seconds):
    """ a really ugly function i need to replace at a later stage """
    logger.debug('Remote end: %s', connection.getpeername())
    logger.debug(' Handshake time: %.3f seconds', seconds)
    logger.debug(" Version: %s", connection.getVersionName())
    logger.debug(" Cipher: %s %s", connection.getCipherName(), connection.getCipherImplementation())
    logger.debug(" Ciphersuite: %s", CipherSuite.ietfNames[connection.session.cipherSuite])

    if connection.session.clientCertChain:
        logger.debug(" Client X.509 SHA1 fingerprint: %s", connection.session.clientCertChain.getFingerprint())
    else:
        logger.debug(" No client certificate provided by peer")
    if connection.session.serverCertChain:
        logger.debug(" Server X.509 SHA1 fingerprint: %s", connection.session.serverCertChain.getFingerprint())
    if connection.session.srpUsername:
        logger.debug(" Client SRP username: %s", connection.session.srpUsername)
    if connection.version >= (3, 3) and connection.serverSigAlg is not None:
        scheme = SignatureScheme.toRepr(connection.serverSigAlg)
        if scheme is None:
            scheme = "{1}+{0}".format(HashAlgorithm.toStr(connection.serverSigAlg[0]), SignatureAlgorithm.toStr(connection.serverSigAlg[1]))
        logger.debug(" Key exchange signature: %s", scheme)
    if connection.ecdhCurve is not None:
        logger.debug(" Group used for key exchange: %s", GroupName.toStr(connection.ecdhCurve))
    if connection.dhGroupSize is not None:
        logger.debug(" DH group size: %s bits", connection.dhGroupSize)
    if connection.session.serverName:
        logger.debug(" SNI: %s", connection.session.serverName)
    if connection.session.appProto:
        logger.debug(" Application Layer Protocol negotiated: %s", connection.session.appProto.decode('utf-8'))
    logger.debug(" Next-Protocol Negotiated: %s", connection.next_proto)
    logger.debug(" Encrypt-then-MAC: %s", connection.encryptThenMAC)
    logger.debug(" Extended Master Secret: %s", connection.extendedMasterSecret)

def convert_byte_to_string(value):
    """ convert a variable to string if needed """
    if hasattr(value, 'decode'):
        try:
            return value.decode()
        except BaseException:
            return value
    else:
        return value

def convert_string_to_byte(value):
    """ convert a variable to byte if needed """
    if hasattr(value, 'encode'):
        result = value.encode()
    else:
        result = value
    return result

def logger_setup(debug, cfg_file=None):
    """ setup logger """
    if debug:
        log_mode = logging.DEBUG
    else:
        log_mode = logging.INFO

    # define log format
    config_dic = config_load(cfg_file=cfg_file)
    log_format = config_dic.get('LOGGING', 'log_format', fallback='%(message)s')

    logging.basicConfig(format=log_format, datefmt="%Y-%m-%d %H:%M:%S", level=log_mode)
    logger = logging.getLogger('est_proxy')
    return logger

def hssrv_options_get(logger, task, config_dic):
    """ get parameters for handshake server """
    logger.debug('hssrv_options_get({0})'.format(task))

    hs_settings = HandshakeSettings()

    #  settings.useExperimentalTackExtension=True
    # settings.dhParams = dhparam
    # if ssl3:
    #    settings.minVersion = (3, 0)
    #
    # if cipherlist:
    #    settings.cipherNames = [item for cipher in cipherlist
    #                            for item in cipher.split(',')]

    option_dic = {}
    if task == 'ClientAuth':
        if 'ClientAuth' in config_dic:
            if 'cert_file' in config_dic['ClientAuth'] and 'key_file' in config_dic['ClientAuth']:
                # logger.error('Helper.hssrv_options_get(): ClientAuth specified but not configured in config file')
                option_dic['certChain'] = config_dic['ClientAuth']['cert_file']
                option_dic['privateKey'] = config_dic['ClientAuth']['key_file']
                option_dic['sessionCache'] = SessionCache()
                option_dic['alpn'] = [bytearray(b'http/1.1')]
                option_dic['settings'] = hs_settings
                option_dic['reqCert'] = True
                option_dic['sni'] = None
            else:
                logger.error('Helper.hssrv_options_get(): incomplete ClientAuth configuration in config file')
        else:
            logger.error('Helper.hssrv_options_get(): ClientAuth specified but not configured in config file')

    return option_dic
