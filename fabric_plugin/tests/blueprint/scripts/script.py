#!/usr/bin/python

import os

from cloudify import ctx


def test_run_python_script():
    ctx.instance.runtime_properties['test_value'] = \
        os.environ.get('test_value')


def test_nested_property():
    ctx.instance.runtime_properties['test_value'] = {'dict': ['some_value']}

    # check that we can access the dict (that we receive it back as a dict,
    # not as a string)
    retrieved = ctx.instance.runtime_properties['test_value']['dict'][0]

    # the test method's check is that rp['test_value'] = 'some_value'
    # after the test, so let's conform to that
    ctx.instance.runtime_properties['test_value'] = retrieved


globals()[os.environ.get('test_operation')]()
