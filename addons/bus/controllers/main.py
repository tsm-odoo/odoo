# Part of Odoo. See LICENSE file for full copyright and licensing details.

import json
import logging

from odoo.http import Controller, request, route
from odoo.websocket import ws_request
from odoo.addons.bus.models.bus import dispatch

class BusController(Controller):
    @route('/longpolling/im_status', type="json", auth="user")
    def im_status(self, partner_ids):
        return request.env['res.partner'].with_context(active_test=False).search([('id', 'in', partner_ids)]).read(['im_status'])

    @route('/longpolling/health', type='http', auth='none', save_session=False)
    def health(self):
        data = json.dumps({
            'status': 'pass',
        })
        headers = [('Content-Type', 'application/json'),
                   ('Cache-Control', 'no-store')]
        return request.make_response(data, headers)

    # ------------------------------------------------------
    # WEBSOCKETS ROUTES
    # ------------------------------------------------------

    def _subscribe(self, channels, last):
        """ Override this method to add channels """
        channels = list(channels)  # do not alter original list
        channels.append('broadcast')
        dispatch.subscribe(ws_request.ws, ws_request.db, channels, last)

    @route('/subscribe', type="websocket", auth="public")
    def subscribe(self, channels, last=0):
        if not ws_request.registry.in_test_mode():
            self._subscribe(channels, last)

    @route('/update_presence', type="websocket", auth="public")
    def update_presence(self, inactivity_period):
        if ws_request.session.uid:
            ws_request.env['bus.presence'].update(
                inactivity_period, identity_field='user_id', identity_value=ws_request.session.uid)
