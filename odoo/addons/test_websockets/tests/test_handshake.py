# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

from odoo.tests import common


@common.tagged('post_install', '-at_install')
class TestWebsocketHandshake(common.HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._headers = {
            'Sec-WebSocket-Version': '13',
            'Sec-WebSocket-Key': 'l5WWdfI8NbYhz7lp0/UBoQ==',
            'Connection': 'Upgrade',
            'Upgrade': 'websocket'
        }
        cls._ws_url = '/websocket'

    def test_missing_headers(self):
        response = self.url_open(self._ws_url, headers={})
        self.assertEqual(response.status_code, 400)
        fail_reason = response._content.decode('utf-8')
        self.assertIn('sec-websocket-version', fail_reason)
        self.assertIn('sec-websocket-key', fail_reason)
        self.assertIn('upgrade', fail_reason)

    def test_empty_headers(self):
        headers = {header: '' for header, _ in self._headers.items()}
        response = self.url_open(self._ws_url, headers=headers)
        self.assertEqual(response.status_code, 400)
        fail_reason = response._content.decode('utf-8')
        self.assertIn('sec-websocket-version', fail_reason)
        self.assertIn('sec-websocket-key', fail_reason)
        self.assertIn('connection', fail_reason)
        self.assertIn('upgrade', fail_reason)

    def test_invalid_version(self):
        headers = dict(self._headers)
        headers['Sec-WebSocket-Version'] = 'invalid_version'
        response = self.url_open(self._ws_url, headers=headers)
        self.assertEqual(response.status_code, 426)
        self.assertIn('Sec-WebSocket-Version', response.headers)
