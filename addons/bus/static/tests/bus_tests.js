odoo.define('web.bus_tests', function (require) {
"use strict";

var BusService = require('bus.BusService');
var AbstractStorageService = require('web.AbstractStorageService');
var RamStorage = require('web.RamStorage');
var testUtils = require('web.test_utils');
var Widget = require('web.Widget');
const LegacyRegistry = require("web.Registry");
const { ConnectionLostError } = require("@web/core/network/rpc_service");
const { patchWithCleanup, nextTick } = require("@web/../tests/helpers/utils");
const { createWebClient } =  require('@web/../tests/webclient/helpers');


var LocalStorageServiceMock;

QUnit.module('Bus', {
    beforeEach: function () {
        LocalStorageServiceMock = AbstractStorageService.extend({storage: new RamStorage()});
    },
}, function () {
    QUnit.test('notifications received from the longpolling channel', async function (assert) {
        assert.expect(6);

        var pollPromise = testUtils.makeTestPromise();

        var parent = new Widget();
        await testUtils.mock.addMockEnvironment(parent, {
            data: {},
            services: {
                bus_service: BusService,
                local_storage: LocalStorageServiceMock,
            },
            mockRPC: function (route, args) {
                if (route === '/longpolling/poll') {
                    assert.step(route + ' - ' + args.channels.join(','));

                    pollPromise = testUtils.makeTestPromise();
                    pollPromise.abort = (function () {
                        this.reject({message: "XmlHttpRequestError abort"}, $.Event());
                    }).bind(pollPromise);
                    return pollPromise;
                }
                return this._super.apply(this, arguments);
            }
        });

        var widget = new Widget(parent);
        await widget.appendTo($('#qunit-fixture'));

        widget.call('bus_service', 'onNotification', this, function (notifications) {
            assert.step('notification - ' + notifications.toString());
        });
        widget.call('bus_service', 'addChannel', 'lambda');

        pollPromise.resolve([{
            message: 'beta',
        }]);
        await testUtils.nextTick();

        pollPromise.resolve([{
            message: 'epsilon',
        }]);
        await testUtils.nextTick();

        assert.verifySteps([
            '/longpolling/poll - lambda',
            'notification - beta',
            '/longpolling/poll - lambda',
            'notification - epsilon',
            '/longpolling/poll - lambda',
        ]);

        parent.destroy();
    });

    QUnit.test('longpolling restarts when connection is lost', async function (assert) {
        assert.expect(4);
        const legacyRegistry = new LegacyRegistry();
        legacyRegistry.add("bus_service", BusService);
        legacyRegistry.add("local_storage", LocalStorageServiceMock);

        const oldSetTimeout = window.setTimeout;
        patchWithCleanup(
            window,
            {
                setTimeout: callback => oldSetTimeout(callback, 0)
            },
            { pure: true },
        )

        let busService;
        let rpcCount = 0;
        // Using createWebclient to get the compatibility layer between the old services and the new
        await createWebClient({
            mockRPC(route) {
                if (route === '/longpolling/poll') {
                    rpcCount++;
                    assert.step(`polling ${rpcCount}`);
                    if (rpcCount == 1) {
                        return Promise.reject(new ConnectionLostError());
                    }
                    assert.equal(rpcCount, 2, "Should not be called after stopPolling");
                    busService.stopPolling();
                    return Promise.reject(new ConnectionLostError());
                }
            },
            legacyParams: { serviceRegistry: legacyRegistry },
        });
        busService = owl.Component.env.services.bus_service;
        busService.startPolling();
        // Give longpolling bus a tick to try to restart polling
        await nextTick();

        assert.verifySteps([
            "polling 1",
            "polling 2",
        ]);
    });
});

});
