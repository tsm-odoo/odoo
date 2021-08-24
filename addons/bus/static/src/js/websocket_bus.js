/** @odoo-module **/

/**
 * Event Websocket bus used to bind events on websocket notifications
 *
 * trigger:
 * - window_focus : when the window focus change (true for focused, false for blur)
 * - notification : when a notification is received from the websocket service
 */
export class WebsocketBus {
    constructor(env, websocketService) {
        this.env = env;
        this.websocketService = websocketService;
        this._id = _.uniqueId('bus');
        this._channels = [];
        this._hasSubscribed = false;
        this._isOdooFocused = true;
        this._bus = new owl.core.EventBus();
        this.userUpdatePeriod = 30000; // update user presence every 30s

        // bus presence
        this._lastPresenceTime = new Date().getTime();
        $(window).on("focus." + this._id, this._onFocusChange.bind(this, {focus: true}));
        $(window).on("blur." + this._id, this._onFocusChange.bind(this, {focus: false}));
        $(window).on("unload." + this._id, this._onFocusChange.bind(this, {focus: false}));

        $(window).on("click." + this._id, this._onPresence.bind(this));
        $(window).on("keydown." + this._id, this._onPresence.bind(this));
        $(window).on("keyup." + this._id, this._onPresence.bind(this));

        this.on = this._bus.on.bind(this._bus);
        this.off = this._bus.off.bind(this._bus);
        this.trigger = this._bus.trigger.bind(this._bus);

        this._startUpdateUserPresenceLoop();
        websocketService.on('disconnect', this, this._onDisconnect);
        websocketService.on('reconnect', this, this._onReconnect);
    }

    //--------------------------------------------------------------------------
    // Public
    //--------------------------------------------------------------------------

    /**
    * Register a new channel to listen to bus notifications (ignore if already
    * listening on this channel).
    *
    * @param {string} channel
    */
    addChannel(channel) {
        if (this._channels.indexOf(channel) === -1) {
            this._channels.push(channel);
            this.updateChannels();
        }
    }

    /**
     * Unregister a channel from bus notifications.
     *
     * @param {string} channel
     */
    deleteChannel(channel) {
        var index = this._channels.indexOf(channel);
        if (index !== -1) {
            this._channels.splice(index, 1);
            this.updateChannels();
        }
    }

    /**
     * Tell whether odoo is focused or not
     *
     * @returns {boolean}
     */
    isOdooFocused() {
        return this._isOdooFocused;
    }

    /**
     * Start the bus by subscribing to this._channels. Usually, the bus starts
     * when a channel is added. Some modules add their channels server side
     * which mean they need to start the bus manually.
     */
    startBus() {
        if (!this._hasSubscribed) {
            this.updateChannels();
        }
    }

    /**
     * @private
     */
    updateChannels() {
        this.send('/subscribe', {
            channels: this._channels,
        });
        this._hasSubscribed = true;
    }

    /**
     * Send a message through the socket.
     *
     * @param {string} path The route to target on the server
     * @param {any} data Data to pass to the route
     */
    send(path, data) {
        this.websocketService.send({path, data});
    }

    //--------------------------------------------------------------------------
    // Private
    //--------------------------------------------------------------------------

    /**
     * Update user presence every this.userUpdatePeriod seconds.
     *
     * @private
     */
    _startUpdateUserPresenceLoop() {
        const updateUserPresence = () => {
            const now = new Date().getTime();
            this.send("/update_presence", {
                inactivity_period: now - this._lastPresenceTime
            });
        };
        updateUserPresence();
        this._userPresenceInterval = setInterval(
            updateUserPresence,
            this.userUpdatePeriod,
        );
    }

    //--------------------------------------------------------------------------
    // Handlers
    //--------------------------------------------------------------------------

    /**
     * Handler when the focus of the window change.
     * Trigger the 'window_focus' event.
     *
     * @private
     * @param {Object} params
     * @param {Boolean} params.focus
     */
    _onFocusChange(params) {
        this._isOdooFocused = params.focus;
        if (params.focus) {
            this._lastPresenceTime = new Date().getTime();
            this.trigger('window_focus', this._isOdooFocused);
        }
    }

    /**
     * Handler when there is an activity on the window (click, keydown, keyup)
     * Update the last presence date.
     *
     * @private
     */
    _onPresence() {
        this._lastPresenceTime = new Date().getTime();
    }

    _onDisconnect() {
        this._hasSubscribed = false;
        clearInterval(this._userPresenceInterval);
    }

    _onReconnect() {
        this._startUpdateUserPresenceLoop();
        this.updateChannels();
    }
}
