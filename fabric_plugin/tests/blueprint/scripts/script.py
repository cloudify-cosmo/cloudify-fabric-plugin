#!/usr/bin/python

import os

from cloudify import ctx


def test_run_python_script():
    ctx.instance.runtime_properties['test_value'] = \
        os.environ.get('test_value')


globals()[os.environ.get('test_operation')]()
