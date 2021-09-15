# -*- coding: utf-8 -*-
import datetime
import json
import logging
import select
import threading
import time

import odoo
from odoo import api, fields, models, SUPERUSER_ID
from odoo.tools.misc import DEFAULT_SERVER_DATETIME_FORMAT
from odoo.tools import date_utils
from odoo.websocket import Websocket

_logger = logging.getLogger(__name__)

# longpolling timeout connection
TIMEOUT = 50

#----------------------------------------------------------
# Bus
#----------------------------------------------------------
def json_dump(v):
    return json.dumps(v, separators=(',', ':'), default=date_utils.json_default)

def hashable(key):
    if isinstance(key, list):
        key = tuple(key)
    return key


def channel_with_db(dbname, channel):
    if isinstance(channel, models.Model):
        return (dbname, channel._name, channel.id)
    if isinstance(channel, str):
        return (dbname, channel)
    return channel


class ImBus(models.Model):

    _name = 'bus.bus'
    _description = 'Communication Bus'

    channel = fields.Char('Channel')
    message = fields.Char('Message')

    @api.autovacuum
    def _gc_messages(self):
        timeout_ago = datetime.datetime.utcnow()-datetime.timedelta(seconds=TIMEOUT*2)
        domain = [('create_date', '<', timeout_ago.strftime(DEFAULT_SERVER_DATETIME_FORMAT))]
        return self.sudo().search(domain).unlink()

    @api.model
    def _sendmany(self, notifications):
        channels = set()
        values = []
        for target, notification_type, message in notifications:
            channel = channel_with_db(self.env.cr.dbname, target)
            channels.add(channel)
            values.append({
                'channel': json_dump(channel),
                'message': json_dump({
                    'type': notification_type,
                    'payload': message,
                })
            })
        self.sudo().create(values)
        if channels:
            # We have to wait until the notifications are commited in database.
            # When calling `NOTIFY imbus`, some concurrent threads will be
            # awakened and will fetch the notification in the bus table. If the
            # transaction is not commited yet, there will be nothing to fetch,
            # and the longpolling will return no notification.
            @self.env.cr.postcommit.add
            def notify():
                with odoo.sql_db.db_connect('postgres').cursor() as cr:
                    cr.execute("notify imbus, %s", (json_dump(list(channels)),))

    @api.model
    def _sendone(self, channel, notification_type, message):
        self._sendmany([[channel, notification_type, message]])

    @api.model
    def _poll(self, channels, last=0, options=None):
        if options is None:
            options = {}
        # first poll return the notification in the 'buffer'
        if last == 0:
            timeout_ago = datetime.datetime.utcnow()-datetime.timedelta(seconds=TIMEOUT)
            domain = [('create_date', '>', timeout_ago.strftime(DEFAULT_SERVER_DATETIME_FORMAT))]
        else:  # else returns the unread notifications
            domain = [('id', '>', last)]
        channels = [json_dump(channel_with_db(self.env.cr.dbname, c)) for c in channels]
        domain.append(('channel', 'in', channels))
        notifications = self.sudo().search_read(domain)
        # list of notification to return
        result = []
        for notif in notifications:
            result.append({
                'id': notif['id'],
                'message': json.loads(notif['message']),
            })
        return result


#----------------------------------------------------------
# Dispatcher
#----------------------------------------------------------

class BusSubscription:
    def __init__(self, dbname, channels, last):
        self.last_notification_id = last
        self.channels = channels
        self.dbname = dbname


class ImDispatch(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.name = f'{__name__}.Bus'
        self._ws_to_subscription = {}
        Websocket.onclose(
            lambda ws: self._ws_to_subscription.pop(ws, None)
        )

    def _dispatch_notifications(self, websocket, subscription):
        with odoo.registry(subscription.dbname).cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            notifications = env['bus.bus']._poll(
                subscription.channels, subscription.last_notification_id)
            if notifications:
                subscription.last_notification_id = notifications[-1]['id']
                websocket.send(notifications)

    def subscribe(self, websocket, dbname, channels, last):
        channels = [channel_with_db(dbname, c) for c in channels]
        subscription = self._ws_to_subscription.get(websocket)
        if subscription:
            last = subscription.last_notification_id
        subscription = BusSubscription(dbname, channels, last)
        self._ws_to_subscription[websocket] = subscription
        if not self.is_alive():
            self.start()
        # Dispatch past notifications if there are any
        self._dispatch_notifications(websocket, subscription)

    def loop(self):
        with odoo.sql_db.db_connect('postgres').cursor() as cr:
            connection = cr._cnx
            cr.execute("listen imbus")
            cr.commit()
            while True:
                select.select([connection], [], [])
                connection.poll()
                notified_channels = set()
                while connection.notifies:
                    notified_channels.update(
                        hashable(channel) for channel in json.loads(connection.notifies.pop().payload))
                    for websocket, subscription in self._ws_to_subscription.items():
                        if not notified_channels.isdisjoint(subscription.channels):
                            self._dispatch_notifications(websocket, subscription)

    def run(self):
        while True:
            try:
                self.loop()
            except Exception:
                _logger.exception("Bus.loop error, sleep and retry")
                time.sleep(TIMEOUT)

dispatch = None
if not odoo.multi_process or odoo.evented:
    # We only use the event dispatcher in threaded and gevent mode
    dispatch = ImDispatch()
