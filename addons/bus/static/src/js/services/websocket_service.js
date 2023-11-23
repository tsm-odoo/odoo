/** @odoo-module **/
import { browser } from "@web/core/browser/browser";
import { registry } from '@web/core/registry';
import {WebsocketSessionExpiredError, WebsocketInvalidRequestError} from '@bus/js/websocket_errors';


/**
 * Communicate with a SharedWorker in order to provide a single websocket
 * connection shared accross multiple tabs.
 *
 *  @emits connect
 *  @emits disconnect
 *  @emits reconnect
 *  @emits reconnecting
 *  @emits server_error
 *  @emits message
 */
export const websocketService = {
    _removeConnectionLostNotification: null,
    CLOSE_CODES: Object.freeze({
        INVALID_DATABASE: 4001,
        SESSION_EXPIRED: 4002,
        INVALID_REQUEST: 4003,
    }),

    async start(env) {
        this.env = env;
        this._bus = new owl.core.EventBus();
        if ('SharedWorker' in window) {
            this.worker = new browser.SharedWorker(
                '/bus/static/src/js/workers/websocket_shared_worker.js',
                {name: "odoo:websocket_shared_worker"});
            this.worker.port.start();
            this.worker.port.addEventListener('message', this._handleMessage.bind(this));
        } else {
            // Fallback for browsers which does not support SharedWorker.
            this.worker = new browser.Worker(
                '/bus/static/src/js/workers/websocket_simple_worker.js',
                {name: "odoo:websocket_worker"});
            this.worker.addEventListener('message', this._handleMessage.bind(this));
            this.send = message => this.worker.postMessage(message);
        }
        return {
            send: this.send.bind(this),
            on: this._bus.on.bind(this._bus),
            off: this._bus.off.bind(this._bus),
        };
    },

   //--------------------------------------------------------------------------
   // PUBLIC
   //--------------------------------------------------------------------------

    /**
     * Send a message through the socket.
     *
     * @param {any} message
     */
    send(message) {
        this.worker.port.postMessage(message);
    },

   //--------------------------------------------------------------------------
   // PRIVATE
   //--------------------------------------------------------------------------

    /**
     * Handle messages received from the shared worker and fires an event
     * according to the message type.
     *
     * @param {MessageEvent} messageEv
     * @param {{type: MessageType, data: any}[]}  messageEv.data
     */
    _handleMessage(messageEv) {
        const {type, payload} = messageEv.data;
        if (type === 'reconnecting') {
            if (!this._removeConnectionLostNotification) {
                this._removeConnectionLostNotification = this.env.services.notification.add(
                    this.env._t("Websocket connection lost. Trying to reconnect..."),
                    { sticky: true },
                );
            }
        } else if (type === 'reconnect') {
            this._removeConnectionLostNotification();
            this._removeConnectionLostNotification = null;
        } else if (type === 'disconnect') {
            if (payload.code !== 1000) {
                this._handleAbnormalClosure(payload);
            }
        }
        this._bus.trigger(type, payload);
    },
    /**
     * Called when the websocket was closed unexpectedly (ie. code is not 1000).
     *
     * @param {{code: number, reason: string}} data
     */
    _handleAbnormalClosure(data) {
        const {code, reason} = data;
        switch (code) {
            case this.CLOSE_CODES.SESSION_EXPIRED:
                throw new WebsocketSessionExpiredError();
            case this.CLOSE_CODES.INVALID_REQUEST:
                throw new WebsocketInvalidRequestError(reason);
            case this.CLOSE_CODES.INVALID_DATABASE:
                window.location.replace('/web/database/selector');
                break;
        }
    }
};

export function makeLegacyWebsocketService(legacyEnv) {
    return {
        dependencies: ['websocketService'],
        start(env, { websocketService }) {
            legacyEnv.services.websocketService = websocketService;
        },
    };
}

registry.category('services').add('websocketService', websocketService);
