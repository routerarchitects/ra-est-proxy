#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for esthandler """
# pylint: disable= C0415, W0212
import unittest
import sys
import os
from unittest.mock import patch, Mock
import tempfile

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class EsthanderTestCases(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        from est_proxy.est_handler import ESTSrvHandler
        self.esthandler = ESTSrvHandler.__new__(ESTSrvHandler)
        self.esthandler.logger = logging.getLogger('test_est')

    def test_001__cacerts_split(self):
        """ _cacerts_split() two certs """
        ca_certs = """
foo
-----END CERTIFICATE-----
bar
-----END CERTIFICATE-----
"""
        result = ['\nfoo\n-----END CERTIFICATE-----\n', 'bar\n-----END CERTIFICATE-----\n']
        self.assertEqual(result, self.esthandler._cacerts_split(ca_certs))

    def test_002__cacerts_split(self):
        """ _cacerts_split() one cert """
        ca_certs = """
foo
-----END CERTIFICATE-----
"""
        result = ['\nfoo\n-----END CERTIFICATE-----\n']
        self.assertEqual(result, self.esthandler._cacerts_split(ca_certs))

    def test_003__cacerts_split(self):
        """ _cacerts_split() certs none """
        ca_certs = None
        result = []
        self.assertEqual(result, self.esthandler._cacerts_split(ca_certs))

    def test_004__cacerts_split(self):
        """ _cacerts_split() certs is a bogus string """
        ca_certs = 'string'
        result = []
        self.assertEqual(result, self.esthandler._cacerts_split(ca_certs))

    @patch('tempfile.NamedTemporaryFile')
    def test_005__cacerts_dump(self, mock_nf):
        """ _cacerts_dump() two certs """
        obj1 = Mock()
        obj1.name = 'foo_ret'
        obj2 = Mock()
        obj2.name = 'bar_ret'
        mock_nf.side_effect = [obj1, obj2]
        result = ['foo_ret', 'bar_ret']
        self.assertEqual(result, self.esthandler._cacerts_dump(['foo', 'bar']))

    @patch('tempfile.NamedTemporaryFile')
    def test_006_cacerts_dump(self, mock_nf):
        """ _cacerts_dump() two certs """
        obj1 = Mock()
        obj1.name = 'foo_ret'
        mock_nf.side_effect = [obj1]
        result = ['foo_ret']
        self.assertEqual(result, self.esthandler._cacerts_dump(['foo']))

    @patch('tempfile.NamedTemporaryFile')
    def test_007_cacerts_dump(self, mock_nf):
        """ _cacerts_dump() empty list   """
        obj1 = Mock()
        obj1.name = 'foo_ret'
        mock_nf.side_effect = [obj1]
        self.assertFalse(self.esthandler._cacerts_dump([]))

    @patch('tempfile.NamedTemporaryFile')
    def test_008_cacerts_dump(self, mock_nf):
        """ _cacerts_dump() empty list   """
        obj1 = Mock()
        obj1.name = 'foo_ret'
        mock_nf.side_effect = [obj1]
        self.assertFalse(self.esthandler._cacerts_dump('foo'))

    def test_009__opensslcmd_build(self):
        """ _opensslcmd_build two certs """
        self.esthandler.openssl_bin = 'openssl'
        file_name_list = ['foo', 'bar']
        pkcs7_file = 'pkcs7_file'
        result = ['openssl', 'crl2pkcs7', '-nocrl', '-out', 'pkcs7_file', '--certfile', 'foo', '--certfile', 'bar']
        self.assertEqual(result, self.esthandler._opensslcmd_build(file_name_list, pkcs7_file))

    def test_010__opensslcmd_build(self):
        """ _opensslcmd_build one certs """
        self.esthandler.openssl_bin = 'openssl'
        file_name_list = ['foo']
        pkcs7_file = 'pkcs7_file'
        result = ['openssl', 'crl2pkcs7', '-nocrl', '-out', 'pkcs7_file', '--certfile', 'foo']
        self.assertEqual(result, self.esthandler._opensslcmd_build(file_name_list, pkcs7_file))

    def test_011__opensslcmd_build(self):
        """ _opensslcmd_build two certs """
        self.esthandler.openssl_bin = 'openssl'
        file_name_list = ['foo1', 'foo2', 'foo3']
        pkcs7_file = 'pkcs7_file'
        result = ['openssl', 'crl2pkcs7', '-nocrl', '-out', 'pkcs7_file', '--certfile', 'foo1', '--certfile', 'foo2', '--certfile', 'foo3']
        self.assertEqual(result, self.esthandler._opensslcmd_build(file_name_list, pkcs7_file))

    def test_012__opensslcmd_build(self):
        """ _opensslcmd_build one certs in list as string """
        self.esthandler.openssl_bin = 'openssl'
        file_name_list = 'foo'
        pkcs7_file = 'pkcs7_file'
        result = ['openssl', 'crl2pkcs7', '-nocrl', '-out', 'pkcs7_file', '--certfile', 'foo']
        self.assertEqual(result, self.esthandler._opensslcmd_build(file_name_list, pkcs7_file))

    def test_013__opensslcmd_build(self):
        """ _opensslcmd_build one certs in list as string """
        self.esthandler.openssl_bin = 'openssl'
        file_name_list = b'foo'
        pkcs7_file = 'pkcs7_file'
        result = ['openssl', 'crl2pkcs7', '-nocrl', '-out', 'pkcs7_file', '--certfile', 'foo']
        self.assertEqual(result, self.esthandler._opensslcmd_build(file_name_list, pkcs7_file))

    def test_014___pkcs7_clean(self):
        """ _pkcs7_clean() certs ok """
        pkcs7 = '-----BEGIN PKCS7-----foo-----END PKCS7-----'
        result = 'foo'
        self.assertEqual(result, self.esthandler._pkcs7_clean(pkcs7))

    def test_015___pkcs7_clean(self):
        """ _pkcs7_clean() hast just END tag """
        pkcs7 = 'foo-----END PKCS7-----'
        result = 'foo'
        self.assertEqual(result, self.esthandler._pkcs7_clean(pkcs7))

    def test_016___pkcs7_clean(self):
        """ _pkcs7_clean() just BEGIN tag """
        pkcs7 = '-----BEGIN PKCS7-----foo'
        result = 'foo'
        self.assertEqual(result, self.esthandler._pkcs7_clean(pkcs7))

    def test_017___pkcs7_clean(self):
        """ _pkcs7_clean() pcs#7 None """
        pkcs7 = None
        result = 'foo'
        self.assertFalse(self.esthandler._pkcs7_clean(pkcs7))

    def test_018___pkcs7_clean(self):
        """ _pkcs7_clean() pcs#7 int """
        pkcs7 = 8
        self.assertEqual(8, self.esthandler._pkcs7_clean(pkcs7))

    def test_019___pkcs7_clean(self):
        """ _pkcs7_clean() pcs#7 byte """
        pkcs7 = b'-----BEGIN PKCS7-----foo-----END PKCS7-----'
        result = 'foo'
        self.assertEqual(result, self.esthandler._pkcs7_clean(pkcs7))

if __name__ == '__main__':
    unittest.main()
