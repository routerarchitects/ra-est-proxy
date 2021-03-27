#!/usr/bin/python
# -*- coding: utf-8 -*-
""" helper functions for est_srv """
from __future__ import print_function
import os
import sys
import logging
import configparser
from tlslite import SessionCache, HandshakeSettings, parseDH
from tlslite.constants import CipherSuite, HashAlgorithm, SignatureAlgorithm, GroupName, SignatureScheme

def config_load(logger=None, mfilter=None, cfg_file=os.path.dirname(__file__)+'/'+'est_proxy.cfg'):
    """ small configparser wrappter to load a config file """
    if logger:
        logger.debug('load_config({1}:{0})'.format(mfilter, cfg_file))
    config = configparser.RawConfigParser()
    config.optionxform = str
    config.read(cfg_file)

    return config

def logger_setup(debug):
    """ setup logger """
    if debug:
        log_mode = logging.DEBUG
    else:
        log_mode = logging.INFO

    # define log format
    config_dic = config_load()
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
        logger.debug('Enable ClientAuth on server side')
        option_dic['certChain'] = config_dic['ClientAuth']['cert_file']
        option_dic['privateKey'] = config_dic['ClientAuth']['key_file']
        option_dic['sessionCache'] = SessionCache()
        option_dic['alpn'] = [bytearray(b'http/1.1')],
        option_dic['settings'] = hs_settings
        option_dic['reqCert'] = True
        option_dic['sni'] = None

    return option_dic

def printgoodconnection(connection, seconds):
    print("  Handshake time: %.3f seconds" % seconds)
    print("  Version: %s" % connection.getVersionName())
    print("  Cipher: %s %s" % (connection.getCipherName(),
        connection.getCipherImplementation()))
    print("  Ciphersuite: {0}".\
            format(CipherSuite.ietfNames[connection.session.cipherSuite]))
    if connection.session.srpUsername:
        print("  Client SRP username: %s" % connection.session.srpUsername)
    if connection.session.clientCertChain:
        print("  Client X.509 SHA1 fingerprint: %s" %
            connection.session.clientCertChain.getFingerprint())
    else:
        print("  No client certificate provided by peer")
    if connection.session.serverCertChain:
        print("  Server X.509 SHA1 fingerprint: %s" %
            connection.session.serverCertChain.getFingerprint())
    if connection.version >= (3, 3) and connection.serverSigAlg is not None:
        scheme = SignatureScheme.toRepr(connection.serverSigAlg)
        if scheme is None:
            scheme = "{1}+{0}".format(
                HashAlgorithm.toStr(connection.serverSigAlg[0]),
                SignatureAlgorithm.toStr(connection.serverSigAlg[1]))
        print("  Key exchange signature: {0}".format(scheme))
    if connection.ecdhCurve is not None:
        print("  Group used for key exchange: {0}".format(GroupName.toStr(connection.ecdhCurve)))
    if connection.dhGroupSize is not None:
        print("  DH group size: {0} bits".format(connection.dhGroupSize))
    if connection.session.serverName:
        print("  SNI: %s" % connection.session.serverName)
    if connection.session.tackExt:
        if connection.session.tackInHelloExt:
            emptyStr = "\n  (via TLS Extension)"
        else:
            emptyStr = "\n  (via TACK Certificate)"
        print("  TACK: %s" % emptyStr)
        print(str(connection.session.tackExt))
    if connection.session.appProto:
        print("  Application Layer Protocol negotiated: {0}".format(
            connection.session.appProto.decode('utf-8')))
    print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    print("  Encrypt-then-MAC: {0}".format(connection.encryptThenMAC))
    print("  Extended Master Secret: {0}".format(connection.extendedMasterSecret))
