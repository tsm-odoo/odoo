# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

from odoo.http import Controller, request, route
from odoo.websocket import WebsocketConnectionHandler


class WebsocketController(Controller):
    """ Handle WebSocket connections """
    @route('/websocket', type="http", auth="public")
    def websocket(self):
        """ Handle the websocket handshake, upgrade the connection if
        successfull """
        return WebsocketConnectionHandler.open_connection(request)
