/** @odoo-module */

import { busService } from "@bus/js/services/bus_service";
import { websocketService } from "@bus/js/services/websocket_service";
import { createWebClient } from "@web/../tests/webclient/helpers";
import { calendarNotificationService } from "@calendar/js/services/calendar_notification_service";
import { click, nextTick, patchWithCleanup } from "@web/../tests/helpers/utils";
import { browser } from "@web/core/browser/browser";
import { registry } from "@web/core/registry";
import { patchWebsocketWithCleanup } from "@web/../tests/helpers/mock_websocket";

const serviceRegistry = registry.category("services");

QUnit.module("Calendar Notification", (hooks) => {
    hooks.beforeEach(() => {
        serviceRegistry.add("websocketService", websocketService);
        serviceRegistry.add("bus_service", busService);
        serviceRegistry.add("calendarNotification", calendarNotificationService);

        patchWithCleanup(browser, {
            setTimeout: (fn) => fn(),
            clearTimeout: () => {},
        });

        const calendarAlarmNotification = [{
            message: {
                type: "calendar.alarm",
                payload: [{
                    alarm_id: 1,
                    event_id: 2,
                    title: "Meeting",
                    message: "Very old meeting message",
                    timer: 20 * 60,
                    notify_at: "1978-04-14 12:45:00",
                }],
            }
        }];

        // trigger a message event containing the calendar alarm notification
        // once the websocket bus is started.
        patchWebsocketWithCleanup({
            send: function (message) {
                const { path } = JSON.parse(message);
                if (path === '/subscribe') {
                    this.dispatchEvent(new MessageEvent('message', {
                        data: JSON.stringify(calendarAlarmNotification),
                    }));
                }
            }
        });
    });

    QUnit.test(
        "can listen on bus and display notifications in DOM and click OK",
        async (assert) => {
            assert.expect(5);

            const mockRPC = (route, args) => {
                if (route === "/calendar/notify") {
                    return Promise.resolve([]);
                }
                if (route === "/calendar/notify_ack") {
                    assert.step("notifyAck");
                    return Promise.resolve(true);
                }
            };

            const webClient = await createWebClient({ mockRPC });

            await nextTick();

            assert.containsOnce(webClient.el, ".o_notification_body");
            assert.strictEqual(
                webClient.el.querySelector(".o_notification_body .o_notification_content")
                    .textContent,
                "Very old meeting message"
            );

            await click(webClient.el.querySelector(".o_notification_buttons .btn"));
            assert.verifySteps(["notifyAck"]);
            assert.containsNone(webClient.el, ".o_notification");
        }
    );

    QUnit.test(
        "can listen on bus and display notifications in DOM and click Detail",
        async (assert) => {
            assert.expect(5);

            const mockRPC = (route, args) => {
                if (route === "/calendar/notify") {
                    return Promise.resolve([]);
                }
            };

            const fakeActionService = {
                name: "action",
                start() {
                    return {
                        doAction(actionId) {
                            assert.step(actionId);
                            return Promise.resolve(true);
                        },
                        loadState(state, options) {
                            return Promise.resolve(true);
                        },
                    };
                },
            };
            serviceRegistry.add("action", fakeActionService, { force: true });

            const webClient = await createWebClient({ mockRPC });

            await nextTick();

            assert.containsOnce(webClient.el, ".o_notification_body");
            assert.strictEqual(
                webClient.el.querySelector(".o_notification_body .o_notification_content")
                    .textContent,
                "Very old meeting message"
            );

            await click(webClient.el.querySelectorAll(".o_notification_buttons .btn")[1]);
            assert.verifySteps(["calendar.action_calendar_event_notify"]);
            assert.containsNone(webClient.el, ".o_notification");
        }
    );

    QUnit.test(
        "can listen on bus and display notifications in DOM and click Snooze",
        async (assert) => {
            assert.expect(4);

            const mockRPC = (route, args) => {
                if (route === "/calendar/notify") {
                    return Promise.resolve([]);
                }
                if (route === "/calendar/notify_ack") {
                    assert.step("notifyAck");
                    return Promise.resolve(true);
                }
            };

            const webClient = await createWebClient({ mockRPC });

            await nextTick();

            assert.containsOnce(webClient.el, ".o_notification_body");
            assert.strictEqual(
                webClient.el.querySelector(".o_notification_body .o_notification_content")
                    .textContent,
                "Very old meeting message"
            );

            await click(webClient.el.querySelectorAll(".o_notification_buttons .btn")[2]);
            assert.verifySteps([], "should only close the notification withtout calling a rpc");
            assert.containsNone(webClient.el, ".o_notification");
        }
    );
});
