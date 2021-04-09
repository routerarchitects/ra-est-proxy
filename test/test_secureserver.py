#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for secureserver.py """
# pylint: disable= C0415, W0212
import unittest
import configparser
import sys
import os
from unittest.mock import patch, Mock

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class SecureserverTestCases(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_est')
        from est_proxy.secureserver import SecureServer
        self.secureserver = SecureServer.__new__(SecureServer)

    @patch('est_proxy.secureserver.config_load')
    @patch('est_proxy.secureserver.logger_setup')
    def test_001_config_load(self, mock_logger, mock_load_cfg):
        """ test _config_load empty dictionary """
        mock_logger.return_value = None
        mock_load_cfg.return_value = {}
        self.secureserver._config_load()
        self.assertFalse(self.secureserver.config_dic['connection_log'])
        self.assertFalse(self.secureserver.debug)

    @patch('est_proxy.secureserver.config_load')
    @patch('est_proxy.secureserver.logger_setup')
    def test_002_config_load(self, mock_logger, mock_load_cfg):
        """ test _config_load empty dictionary """
        mock_logger.return_value = None
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.secureserver._config_load()
        self.assertFalse(self.secureserver.config_dic['connection_log'])
        self.assertFalse(self.secureserver.debug)

    @patch('est_proxy.secureserver.config_load')
    @patch('est_proxy.secureserver.logger_setup')
    def test_003_config_load(self, mock_logger, mock_load_cfg):
        """ test _config_load debug False """
        mock_logger.return_value = None
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {'foo': 'bar', 'debug': False}
        mock_load_cfg.return_value = parser
        self.secureserver._config_load()
        self.assertFalse(self.secureserver.config_dic['connection_log'])
        self.assertFalse(self.secureserver.debug)

    @patch('est_proxy.secureserver.config_load')
    @patch('est_proxy.secureserver.logger_setup')
    def test_004_config_load(self, mock_logger, mock_load_cfg):
        """ test _config_load debug False """
        mock_logger.return_value = None
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {'foo': 'bar', 'debug': True}
        mock_load_cfg.return_value = parser
        self.secureserver._config_load()
        self.assertFalse(self.secureserver.config_dic['connection_log'])
        self.assertTrue(self.secureserver.debug)

    @patch('est_proxy.secureserver.config_load')
    @patch('est_proxy.secureserver.logger_setup')
    def test_005_config_load(self, mock_logger, mock_load_cfg):
        """ test _config_load debug False """
        mock_logger.return_value = None
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {'foo': 'bar', 'connection_log': False}
        mock_load_cfg.return_value = parser
        self.secureserver._config_load()
        self.assertFalse(self.secureserver.config_dic['connection_log'])
        self.assertFalse(self.secureserver.debug)

    @patch('est_proxy.secureserver.config_load')
    @patch('est_proxy.secureserver.logger_setup')
    def test_006_config_load(self, mock_logger, mock_load_cfg):
        """ test _config_load debug False """
        mock_logger.return_value = None
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {'foo': 'bar', 'connection_log': True}
        mock_load_cfg.return_value = parser
        self.secureserver._config_load()
        self.assertTrue(self.secureserver.config_dic['connection_log'])
        self.assertFalse(self.secureserver.debug)

    #@patch('est_proxy.secureserver.config_load')
    #def test_007_config_load(self, mock_load_cfg):
    #    """ test _config_load debug False """
    #    # mock_logger.return_value = None
    #    parser = configparser.ConfigParser()
    #    parser['ClientAuth'] = {'key_file': 'bar'}
    #    mock_load_cfg.return_value = parser
    #    with self.assertLogs('test_est', level='INFO') as lcm:
    #        self.secureserver._config_load()
    #    self.assertFalse(self.secureserver.config_dic['connection_log'])
    #    self.assertFalse(self.secureserver.debug)
    #    self.assertIn('foo', lcm.output)


if __name__ == '__main__':
    unittest.main()
