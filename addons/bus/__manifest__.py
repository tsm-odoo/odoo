{
    'name' : 'IM Bus',
    'version': '1.0',
    'category': 'Hidden',
    'description': "Instant Messaging Bus allow you to send messages to users, in live.",
    'depends': ['base', 'web'],
    'data': [
        'security/ir.model.access.csv',
    ],
    'installable': True,
    'assets': {
        'web.assets_backend': [
            'bus/static/src/js/services/assets_watchdog_service.js',
        ],
        'web.assets_common': [
            'bus/static/src/js/websocket_errors.js',
            'bus/static/src/js/services/websocket_service.js',
            'bus/static/src/js/websocket_bus.js',
            'bus/static/src/js/services/bus_service.js',
            'bus/static/src/js/workers/websocket_base_worker.js',
            'bus/static/src/legacy/legacy_setup.js',
        ],
        'web.qunit_suite_tests': [
            'bus/static/tests/*.js',
        ],
        'web.qunit_mobile_suite_tests': [
            'bus/static/tests/test_utils.js',
        ],
    },
    'license': 'LGPL-3',
}
