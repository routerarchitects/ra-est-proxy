#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for esthandler """
# pylint: disable= C0415, E0401, R0904, W0201, W0212
import unittest
import sys
from unittest.mock import patch, Mock, mock_open

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

    @patch('est_proxy.est_handler.ESTSrvHandler._tmpfiles_clean')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_dump')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_split')
    @patch('builtins.open', mock_open(read_data="pkcs7_struc"))
    @patch('subprocess.call')
    def test_019__pkcs7_convert(self, mock_call, mock_split, mock_dmp, mock_clean):
        """ _pkcs7_convert() all ok """
        self.esthandler.openssl_bin = 'openssl'
        mock_call.return_value = 0
        mock_split.return_value = ['foo', 'bar']
        mock_dmp.return_value = ['foo_name', 'bar_name']
        mock_clean.return_value = 0
        self.assertEqual('pkcs7_struc', self.esthandler._pkcs7_convert('cacertss'))

    @patch('tempfile.NamedTemporaryFile')
    @patch('builtins.open', mock_open(read_data="pkcs7_struc"))
    @patch('est_proxy.est_handler.ESTSrvHandler._tmpfiles_clean')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_dump')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_split')
    @patch('subprocess.call')
    def test_020__pkcs7_convert(self, mock_call, mock_split, mock_dmp, mock_clean, mock_nf):
        """ _pkcs7_convert() all ok """
        obj1 = Mock()
        obj1.name = 'mock_nf_ret'
        mock_nf.side_effect = [obj1]
        self.esthandler.openssl_bin = 'openssl'
        mock_call.return_value = 0
        mock_split.return_value = ['foo', 'bar']
        mock_dmp.return_value = ['foo_name', 'bar_name']
        mock_clean.return_value = 0
        self.assertEqual('pkcs7_struc', self.esthandler._pkcs7_convert('cacertss'))

    def test_021__pkcs7_convert(self):
        """ _pkcs7_convert() all no cacerts """
        self.esthandler.openssl_bin = 'openssl'
        self.assertFalse(self.esthandler._pkcs7_convert(None))

    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_dump')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_split')
    def test_022__pkcs7_convert(self, mock_split, mock_dmp):
        """ _pkcs7_convert() no openssl command defined """
        self.esthandler.openssl_bin = None
        mock_split.return_value = ['foo', 'bar']
        mock_dmp.return_value = ['foo_name', 'bar_name']
        self.assertFalse(self.esthandler._pkcs7_convert('cacertss'))

    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_dump')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_split')
    def test_023__pkcs7_convert(self, mock_split, mock_dmp):
        """ _pkcs7_convert() cert dump run into an error """
        self.esthandler.openssl_bin = 'openssl'
        mock_split.return_value = ['foo', 'bar']
        mock_dmp.return_value = []
        self.assertFalse(self.esthandler._pkcs7_convert('cacertss'))

    @patch('tempfile.NamedTemporaryFile')
    @patch('builtins.open', mock_open(read_data="pkcs7_struc"))
    @patch('est_proxy.est_handler.ESTSrvHandler._tmpfiles_clean')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_dump')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_split')
    @patch('subprocess.call')
    def test_024__pkcs7_convert(self, mock_call, mock_split, mock_dmp, mock_clean, mock_nf):
        """ _pkcs7_convert() all ok """
        obj1 = Mock()
        obj1.name = 'mock_nf_ret'
        mock_nf.side_effect = [obj1]
        self.esthandler.openssl_bin = 'openssl'
        mock_call.return_value = 1
        mock_split.return_value = ['foo', 'bar']
        mock_dmp.return_value = ['foo_name', 'bar_name']
        mock_clean.return_value = 0
        self.assertFalse(self.esthandler._pkcs7_convert('cacertss'))

    def test_025_get_process(self):
        """ _get_process() - root path """
        self.esthandler.path = '/'
        self.assertEqual((400, 'text/html', 29, None, b'An unknown error has occured.'), self.esthandler.get_process())

    def test_026_get_process(self):
        """ _get_process() - None as path """
        self.esthandler.path = None
        self.assertEqual((400, 'text/html', 29, None, b'An unknown error has occured.'), self.esthandler.get_process())

    def test_027_get_process(self):
        """ _get_process() - int as path """
        self.esthandler.path = 13
        self.assertEqual((400, 'text/html', 29, None, b'An unknown error has occured.'), self.esthandler.get_process())

    def test_028_get_process(self):
        """ _get_process() - string as path """
        self.esthandler.path = 13
        self.assertEqual((400, 'text/html', 29, None, b'An unknown error has occured.'), self.esthandler.get_process())

    def test_029_get_process(self):
        """ _get_process() - unknown path """
        self.esthandler.path = '/notallowedpath'
        self.assertEqual((400, 'text/html', 29, None, b'An unknown error has occured.'), self.esthandler.get_process())

    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_get')
    def test_030_get_process(self, mock_caget):
        """ _get_process() - ca certs """
        self.esthandler.path = '/.well-known/est/cacerts'
        mock_caget.return_value = 'foobar'
        self.assertEqual((200, 'application/pkcs7-mime', 6, 'base64', b'foobar'), self.esthandler.get_process())

    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_get')
    def test_031_get_process(self, mock_caget):
        """ _get_process() - ca certs """
        self.esthandler.path = '/.well-known/est/cacerts'
        mock_caget.return_value = None
        self.assertEqual((500, 'text/html', 0, None, None), self.esthandler.get_process())

    def test_032_set_response(self):
        """ _set_response() - all ok """
        def dummy_func(*args):
            self.input = args[0].decode('utf-8')
        mock_wfile = Mock()
        mock_wfile.write = dummy_func
        self.esthandler.requestline = 'requestline'
        self.esthandler.client_address = ('127.0.0.1', 12345)
        self.esthandler.request_version = 'request_version'
        self.esthandler.wfile = mock_wfile
        self.esthandler._set_response(code=200, content_type='text/html', clength=100, encoding='utf-8')
        self.assertIn('HTTP/1.1 200 OK', self.input)
        self.assertIn('Content-Type: text/html', self.input)
        self.assertIn('Content-Transfer-Encoding: utf-8', self.input)
        self.assertIn('Content-Length: 100', self.input)
        self.assertIn('Connection: close', self.input)

    def test_033_set_response(self):
        """ _set_response() - no content length code 500 """
        def dummy_func(*args):
            self.input = args[0].decode('utf-8')
        mock_wfile = Mock()
        mock_wfile.write = dummy_func
        self.esthandler.requestline = 'requestline'
        self.esthandler.client_address = ('127.0.0.1', 12345)
        self.esthandler.request_version = 'request_version'
        self.esthandler.wfile = mock_wfile
        self.esthandler._set_response(code=500, content_type='text/html', clength=0, encoding='utf-8')
        self.assertIn('HTTP/1.1 500 Internal Server Error', self.input)
        self.assertIn('Content-Type: text/html', self.input)
        self.assertIn('Content-Transfer-Encoding: utf-8', self.input)
        self.assertIn('Connection: close', self.input)

    def test_034_set_response(self):
        """ _set_response() - code 404 """
        def dummy_func(*args):
            self.input = args[0].decode('utf-8')
        mock_wfile = Mock()
        mock_wfile.write = dummy_func
        self.esthandler.requestline = 'requestline'
        self.esthandler.client_address = ('127.0.0.1', 12345)
        self.esthandler.request_version = 'request_version'
        self.esthandler.wfile = mock_wfile
        self.esthandler._set_response(code=404, content_type='text/html', clength=5, encoding='utf-8')
        self.assertIn('HTTP/1.1 404 Not Found', self.input)
        self.assertIn('Content-Type: text/html', self.input)
        self.assertIn('Content-Transfer-Encoding: utf-8', self.input)
        self.assertIn('Connection: close', self.input)

    def test_035_set_response(self):
        """ _set_response() -  different content length """
        def dummy_func(*args):
            self.input = args[0].decode('utf-8')
        mock_wfile = Mock()
        mock_wfile.write = dummy_func
        self.esthandler.requestline = 'requestline'
        self.esthandler.client_address = ('127.0.0.1', 12345)
        self.esthandler.request_version = 'request_version'
        self.esthandler.wfile = mock_wfile
        self.esthandler._set_response(code=200, content_type='foo', clength=5, encoding='utf-8')
        self.assertIn('HTTP/1.1 200 OK', self.input)
        self.assertIn('Content-Type: foo', self.input)
        self.assertIn('Content-Transfer-Encoding: utf-8', self.input)
        self.assertIn('Connection: close', self.input)

    def test_036_set_response(self):
        """ _set_response() -  different encoding, no content-type """
        def dummy_func(*args):
            self.input = args[0].decode('utf-8')
        mock_wfile = Mock()
        mock_wfile.write = dummy_func
        self.esthandler.requestline = 'requestline'
        self.esthandler.client_address = ('127.0.0.1', 12345)
        self.esthandler.request_version = 'request_version'
        self.esthandler.wfile = mock_wfile
        self.esthandler._set_response(code=200, clength=5, encoding='encoding')
        self.assertIn('HTTP/1.1 200 OK', self.input)
        self.assertIn('Content-Type: text/html', self.input)
        self.assertIn('Content-Transfer-Encoding: encoding', self.input)
        self.assertIn('Connection: close', self.input)


if __name__ == '__main__':
    unittest.main()
