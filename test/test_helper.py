#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for helper """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import datetime
from unittest.mock import patch, MagicMock, Mock

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class HelperTestCases(unittest.TestCase):
    """ test class for helper """
    def setUp(self):
        """ setup """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        from est_proxy.helper import config_load, hssrv_options_get, connection_log
        self.logger = logging.getLogger('test_est')
        self.config_load = config_load
        self.hssrv_options_get = hssrv_options_get
        self.connection_log = connection_log

    def tearDown(self):
        """ teardown test environment """
        # Clean up run after every test method.

    def test_001_allways_ok(self):
        """ a test that never failes """
        self.assertEqual('foo', 'foo')

    def test_002_hssrv_options_get(self):
        """ test handshake options empty config dic and wrong task"""
        config_dic = {}
        task = 'wrong task'
        self.assertEqual({}, self.hssrv_options_get(self.logger, task, config_dic))

    def test_003_hssrv_options_get(self):
        """ test handshake options empty config dic ClientAuth task """
        config_dic = {}
        task = 'ClientAuth'
        expected_log = 'ERROR:test_est:Helper.hssrv_options_get(): ClientAuth specified but not configured in config file'
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.assertEqual({}, self.hssrv_options_get(self.logger, task, config_dic))
        self.assertIn(expected_log, lcm.output)

    def test_004_hssrv_options_get(self):
        """ test handshake options empty config dic ClientAuth task """
        config_dic = {'ClientAuth': {'foo': 'bar'}}
        task = 'ClientAuth'
        expected_log = 'ERROR:test_est:Helper.hssrv_options_get(): incomplete ClientAuth configuration in config file'
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.assertEqual({}, self.hssrv_options_get(self.logger, task, config_dic))
        self.assertIn(expected_log, lcm.output)

    def test_005_hssrv_options_get(self):
        """ test handshake options empty config dic ClientAuth task """
        config_dic = {'ClientAuth': {'cert_file': 'cert_file', 'foo': 'bar'}}
        task = 'ClientAuth'
        expected_log = 'ERROR:test_est:Helper.hssrv_options_get(): incomplete ClientAuth configuration in config file'
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.assertEqual({}, self.hssrv_options_get(self.logger, task, config_dic))
        self.assertIn(expected_log, lcm.output)

    def test_006_hssrv_options_get(self):
        """ test handshake options empty config dic ClientAuth task """
        config_dic = {'ClientAuth': {'cert_file': 'cert_file', 'key_file': 'key_file'}}
        task = 'ClientAuth'
        foo = {'reqCert': True, 'sni': None, 'privateKey': 'key_file', 'certChain': 'cert_file', 'alpn': [bytearray(b'http/1.1')]}
        self.assertTrue(foo.items() <= self.hssrv_options_get(self.logger, task, config_dic).items())

if __name__ == '__main__':
    unittest.main()
