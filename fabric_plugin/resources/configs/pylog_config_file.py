# flake8: NOQA
# IMPORTANT: run "pylog list fake" to see the list of fake data types that can be generated.

import uuid

GENERATOR = {
    'formatters': {
        'json': {
            'type': 'Json',
            'data': {
                'date_time': '$RAND',
                'uuid': [str(uuid.uuid1()) for i in xrange(3)],
                'level': ['ERROR', 'DEBUG'],
                'name': '$RAND',
            }
        },
        'MyApacheErrorFormatter': {
            'type': 'ApacheError',
            'data': {
                'ipv4': ['0.0.0.0']
            }
        },
    },
    'transports': {
        'udp': {
            'type': 'UDP',
            'host': '{{ logstash_host }}',
            'port': {{ logstash_port }},
        }
    },
}
