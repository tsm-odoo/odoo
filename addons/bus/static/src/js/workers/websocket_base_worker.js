/** @odoo-module **/

/**
 * Possible type for the messages sent from the worker to the websocket_service
 *
 * @typedef {'connect' | 'reconnect' | 'disconnect' | 'reconnecting' | 'server_error'} MessageType
 */

/**
 * This class regroups the logic necessary in order for the SharedWorker/Worker to work.
 * Indeed, Safari and some minor browsers does not support SharedWorker. In order to
 * solve this issue, a Worker is used in this case. The logic is almost the same than
 * the one used for SharedWorker and this class implements it.
 */
class WebsocketBaseWorker {
    constructor(websocketURL, websocketClass = WebSocket) {
        this.websocketURL = websocketURL;
        this.websocketClass = websocketClass;
        this.connectRetryDelay = 1000;
        this.connectTimeout = null;
        this.messageWaitQueue = [];
        this.onWebsocketClose = this.onWebsocketClose.bind(this);
        this.onWebsocketError = this.onWebsocketError.bind(this);
        this.onWebsocketMessage = this.onWebsocketMessage.bind(this);
        this.start();
    }

    start() {
        return new Promise(resolve => {
            this.removeWebsocketListeners();
            this.websocket = new this.websocketClass(this.websocketURL);
            this.websocket.addEventListener('open', () => {
                this.messageWaitQueue.forEach(msg => this.websocket.send(msg));
                this.messageWaitQueue = [];
                this.broadcast(this.connectTimeout ? 'reconnect' : 'connect');
                this.connectTimeout = null;
                this.connectRetryDelay = 1000;
                resolve();
            });
            this.websocket.addEventListener('error', this.onWebsocketError);
            this.websocket.addEventListener('message', this.onWebsocketMessage);
            this.websocket.addEventListener('close', this.onWebsocketClose);
        });
    }

    /**
     * Called when a message it posted to the worker. This message is
     * sent through the socket.
     *
     * @param {MessageEvent} messageEv
     */
    onMessage(messageEv) {
        const message = JSON.stringify(messageEv.data);
        if (!this.websocket || this.websocket.readyState !== 1) {
            this.messageWaitQueue.push(message);
        } else {
            this.websocket.send(message);
        }
    }

    /**
    * When notifications are retrieved from the bus, extract them from the event, only keep the
    * message and send them to the clients.
    *
    * @param {MessageEvent} messageEv
    */
    onWebsocketMessage(messageEv) {
        this.broadcast('message', JSON.parse(messageEv.data).map(n => n.message));
    }

    /**
     * Triggered when a connection was established then closed. If closure was not clean (ie. code
     * !== 1000), try to reconnect after indicating to the clients that the connection was closed.
     *
     * @param {CloseEvent} ev
     */
    onWebsocketClose(ev) {
        this.broadcast('disconnect', {code: ev.code, reason: ev.reason});
        if (ev.code !== 1000) {
            this.start();
        }
    }

    /**
     * Triggered when a connection could not be established. Apply an exponential backoff to the
     * reconnect attempts.
     */
    onWebsocketError() {
        // Prevent the close event to be triggered in this case (both close and error events are
        // triggered but only the error event makes sense).
        this.websocket.removeEventListener('close', this.onWebsocketClose);
        this.connectRetryDelay = this.connectRetryDelay * 1.5 + 500 * Math.random();
        this.connectTimeout = setTimeout(this.start.bind(this), this.connectRetryDelay);
        this.broadcast('reconnecting');
    }

    removeWebsocketListeners() {
        if (this.websocket) {
            this.websocket.removeEventListener('message', this.onWebsocketMessage);
            this.websocket.removeEventListener('close', this.onWebsocketClose);
            this.websocket.removeEventListener('error', this.onWebsocketError);
        }
    }

    /**
     * Send the message to all the clients that are connected to the worker.
     *
     * @param {MessageType} type
     * @param {any} payload
     */
    broadcast(type, payload) {
        // To be implemented by workers.
    }

}

// This class is used by the workers (importScript) and by the WebsocketMockWorker class.
// The issue is that one is in an es6 module context while the other is not.
// This means that one need to import this class (which means this class should be exported)
// and the other does not support the es6 module syntax (so export would lead to SyntaxError).
// In order to avoid this problem, this class is added to the global window object if it is defined
// allowing the WebsocketMockWorker class to retrieve it and the workers to import the script
// without syntax error.
if (typeof window !== 'undefined' && window !== null) {
    window.WebsocketBaseWorker = WebsocketBaseWorker;
}
