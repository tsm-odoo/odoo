/** @odoo-module **/

import {SessionExpiredDialog, WarningDialog} from "@web/core/errors/error_dialogs";
import {registry} from "@web/core/registry";

export class WebsocketSessionExpiredError extends Error {}
export function websocketSessionExpiredHandler(env, error, originalError) {
    if (originalError instanceof WebsocketSessionExpiredError) {
        env.services.dialog.add(SessionExpiredDialog);
        return true;
    }
}
registry.category("error_handlers").add("WebsocketSessionExpiredError", websocketSessionExpiredHandler);

export class WebsocketInvalidRequestError extends Error {}
export function websocketInvalidRequestHandler(env, error, originalError) {
    if (originalError instanceof WebsocketInvalidRequestError) {
        env.services.dialog.add(WarningDialog, {
            title: env._t("Websocket request failed"),
            message: originalError.message
        });
        return true;
    }
}
registry.category("error_handlers").add("WebsocketInvalidRequestError", websocketInvalidRequestHandler);
