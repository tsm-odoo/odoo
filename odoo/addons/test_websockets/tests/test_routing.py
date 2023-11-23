# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import unittest
try:
    import websocket
except ImportError:
    websocket = None
import json
import struct
import odoo.tools
from odoo.tests import HOST, common, new_test_user
from odoo.websocket import CloseCode


@common.tagged('post_install', '-at_install')
class TestWebsocketRouting(common.HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if websocket is None:
            cls._logger.warning("websocket-client module is not installed")
            raise unittest.SkipTest("websocket-client module is not installed")
        cls.ws_url = f"ws://{HOST}:{odoo.tools.config['http_port']}/websocket"
        cls.logger_name = 'odoo.websocket'

    def _assert_close_with_code(self, websocket, expected_code):
        opcode, payload = websocket.recv_data()
        # ensure it's a close frame
        self.assertEqual(opcode, 8)
        code = struct.unpack('!H', payload[:2])[0]
        # ensure the close code is the one we expected
        self.assertEqual(code, expected_code)

    def test_access_public_route(self):
        ws = websocket.create_connection(self.ws_url)
        ws.send(json.dumps({
            'path': '/test_access_public_websocket_route',
            'data': {
                'message': 'test_echo_message'
            }
        }))
        self.assertEqual(ws.recv(), 'test_echo_message')
        ws.close(CloseCode.CLEAN)

    def test_access_denied_route(self):
        ws = websocket.create_connection(self.ws_url)
        with self.assertLogs(self.logger_name, level="ERROR"):
            ws.send(json.dumps({
                'path': '/test_access_denied_websocket_route',
            }))
            self._assert_close_with_code(ws, CloseCode.ACCESS_DENIED)

    def test_access_user_route_success(self):
        new_test_user(self.env, login='test_user', password='Password!1')
        user_session = self.authenticate('test_user', 'Password!1')
        ws = websocket.create_connection(self.ws_url, cookie=f"session_id={user_session.sid};")
        ws.send(json.dumps({
            'path': '/test_access_user_websocket_route',
            'data': {
                'message': 'test_echo_message'
            }
        }))
        self.assertEqual(ws.recv(), 'test_echo_message')
        ws.close(CloseCode.CLEAN)

    def test_access_user_route_fail(self):
        # try to access auth=user route without connected user
        ws = websocket.create_connection(self.ws_url)
        with self.assertLogs(self.logger_name, level="ERROR"):
            ws.send(json.dumps({
                'path': '/test_access_user_websocket_route',
                'data': {
                    'message': 'test_echo_message'
                }
            }))
            self._assert_close_with_code(ws, CloseCode.SESSION_EXPIRED)

    def test_call_route_invalid_path(self):
        ws = websocket.create_connection(self.ws_url)
        with self.assertLogs(self.logger_name, level="ERROR"):
            ws.send(json.dumps({
                'path': '/test_non_existing_websocket_path',
            }))
            self._assert_close_with_code(ws, CloseCode.INVALID_REQUEST)

    def test_call_http_route(self):
        ws = websocket.create_connection(self.ws_url)
        with self.assertLogs(self.logger_name, level="ERROR"):
            ws.send(json.dumps({
                'path': '/test_call_http_route_from_websocket',
            }))
            self._assert_close_with_code(ws, CloseCode.INVALID_REQUEST)

    def test_call_route_missing_args(self):
        ws = websocket.create_connection(self.ws_url)
        with self.assertLogs(self.logger_name, level="ERROR"):
            # this route expects a 'message' argument to be passed
            ws.send(json.dumps({
                'path': '/test_access_public_websocket_route'
            }))
            self._assert_close_with_code(ws, CloseCode.INVALID_REQUEST)

    def test_call_route_without_args(self):
        ws = websocket.create_connection(self.ws_url)
        ws.send(json.dumps({
            'path': '/test_websocket_route_without_args',
        }))
        self.assertEqual(json.loads(ws.recv()), True)
        ws.close(CloseCode.CLEAN)

    def test_call_route_invalid_json(self):
        ws = websocket.create_connection(self.ws_url)
        with self.assertLogs(self.logger_name, level="ERROR"):
            ws.send('{invalidjson')
            self._assert_close_with_code(ws, CloseCode.INVALID_REQUEST)
