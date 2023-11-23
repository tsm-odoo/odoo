/** @odoo-module **/
import { browser } from "@web/core/browser/browser";
import { patchWithCleanup } from "@web/../tests/helpers/utils";

export class WebsocketMock extends EventTarget {
    constructor(url, options) {
        super();
        this.readyState = 0;
        this.url = url;
        options = options || {};
        this.onopen = options.onopen || null;
        this.onclose = options.onclose || null;
        this.onmessage = options.onmessage || null;
        this.onerror = options.onerror || null;

        if (options.send) {
            this.send = (data) => {
                this._send(data);
                options.send.call(this, data);
            };
        }
        if (options.close) {
            this.close = (ev) => {
                this._close(ev);
                options.close.call(this, ev);
            };
        }
        queueMicrotask(() => {
            this.readyState = 1;
            const openEv = new Event('open');
            this.dispatchEvent(openEv);
            if (this.onopen) {
                this.onopen(openEv);
            }
        });
    }

    send(data) {
        this._send(data);
    }

    close(code, reason) {
        this._close(code, reason);
    }

    _close(code, reason) {
        this.readyState = 3;
        const closeEv = new CloseEvent('close', {
            code,
            reason,
            wasClean: code === 1000,
        });
        this.dispatchEvent(closeEv);
        if (this.onclose) {
            this.onclose(closeEv);
        }
    }

    _send() {
        if (this.readyState !== 1) {
            const errorEv = new Event('error');
            this.dispatchEvent(errorEv);
            if (this.onerror) {
                this.onerror(errorEv);
            }
            throw new DOMException("Failed to execute 'send' on 'WebSocket': State is not OPEN");
        }
    }
}

export class WebsocketWorkerMock extends EventTarget {
    constructor(scriptURL, options) {
        super();
        this.scriptURL = scriptURL;
        this._worker = new window.WebsocketBaseWorker('wss://random-url.com/websocket', function (url) {
            return new WebsocketMock(url, options || {});
        });
        this._worker.broadcast = (type, payload) => {
            this.dispatchEvent(new MessageEvent('message', {data: {type, payload}}));
        };
    }

    /**
     * @param {*} message
     */
    postMessage(message) {
        this._worker.onMessage(new MessageEvent('message', {data: message}));
    }
}

export class WebsocketSharedWorkerMock extends WebsocketWorkerMock {
    constructor(scriptURL, options) {
        super(scriptURL, options);
        this.port = {
            postMessage: this.postMessage.bind(this),
            addEventListener: this.addEventListener.bind(this),
            removeEventListener: this.removeEventListener.bind(this),
            start: () => {},
        };
    }
}

export function patchWebsocketWithCleanup(options) {
    patchWithCleanup(browser, {
        Worker: function (url) {
            return new WebsocketWorkerMock(url, options);
        },
        SharedWorker: function (url) {
            return new WebsocketSharedWorkerMock(url, options);
        }
    }, { pure: true });
}
