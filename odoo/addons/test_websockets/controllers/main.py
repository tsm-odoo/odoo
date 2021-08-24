# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

from odoo.exceptions import AccessDenied
from odoo.http import Controller, Response, route


class WebsocketController(Controller):
    @route('/test_access_public_websocket_route', type='websocket', auth="public")
    def test_access_public_route(self, message):
        return message

    @route('/test_access_user_websocket_route', type='websocket', auth="user")
    def test_access_user_route(self, message):
        return message

    @route('/test_access_denied_websocket_route', type='websocket', auth="public")
    def test_access_denied_route(self):
        raise AccessDenied()

    @route('/test_websocket_route_without_args', type='websocket', auth="public")
    def test_route_without_args(self):
        return True

    @route('/test_call_http_route_from_websocket', type='http', auth="public")
    def test_call_http_route(self):
        return Response(status=200)
