/** @odoo-module **/
import { registry } from "@web/core/registry";
import { makeLegacyBusService } from "@bus/js/services/bus_service";

(async function setupLegacyBusService() {
    await owl.utils.whenReady();
    registry.category("services").add("legacy_bus_service", makeLegacyBusService(owl.Component.env));
})()
