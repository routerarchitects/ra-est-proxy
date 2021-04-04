#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
# pylint: disable= C0415, W0212
import unittest
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
        self.logger = logging.getLogger('test_a2c')
        from est_proxy.secureserver import SecureServer
        # self.secureserver = SecureServer(None, None, None)

    def test_001_allways_ok(self):
        """ a test that never failes """
        self.assertEqual('foo', 'foo')


if __name__ == '__main__':
    unittest.main()
