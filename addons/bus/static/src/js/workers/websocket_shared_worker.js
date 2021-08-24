/* eslint-env worker */
/* eslint-disable no-restricted-globals */
/* global WebsocketBaseWorker */
importScripts('/bus/static/src/js/workers/websocket_base_worker.js');

const clients = new Set();

class SharedWebsocketWorker extends WebsocketBaseWorker {
    broadcast(type, payload) {
        clients.forEach(c => c.postMessage({type, payload}));
    }
}

const websocketWorker = new SharedWebsocketWorker(
    `${self.location.protocol === 'https:' ? 'wss' : 'ws'}://${self.location.host}/websocket`
);

onconnect = function (e) {
    const currentClient = e.ports[0];
    clients.add(currentClient);
    currentClient.onmessage = msg => websocketWorker.onMessage(msg);
};
