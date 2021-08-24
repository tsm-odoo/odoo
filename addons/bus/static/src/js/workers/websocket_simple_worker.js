/* eslint-env worker */
/* eslint-disable no-restricted-globals */
/* global WebsocketBaseWorker */

importScripts('/bus/static/src/js/workers/websocket_base_worker.js');

class SimpleWebsocketWorker extends WebsocketBaseWorker {
    broadcast(type, payload) {
        postMessage({type, payload});
    }
}

const websocketWorker = new SimpleWebsocketWorker(
    `${self.location.protocol === 'https:' ? 'wss' : 'ws'}://${self.location.host}/websocket`
);
self.onmessage = msg => websocketWorker.onMessage(msg);
