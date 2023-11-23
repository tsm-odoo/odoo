/** @odoo-module **/
import { busService } from "@bus/js/services/bus_service";

export function makeFakeBusService(params = {}) {
    return {
        ...busService,
        start() {
            const fakeBusService = busService.start(...arguments);
            Object.assign(fakeBusService, {
                // compatibility with legacy services mock
                isDestroyed: () => false,
                ...params,
            });
            return fakeBusService;
        }
    };
}
