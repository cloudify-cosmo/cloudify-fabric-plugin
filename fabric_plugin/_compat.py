########
# Copyright (c) 2019 Cloudify Platform Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

"""Python 2 + 3 compatibility utils"""
# flake8: noqa

import sys
PY2 = sys.version_info[0] == 2


if PY2:
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO
    exec("""
def exec_(code, globs):
    exec code in globs
""")

else:
    from io import StringIO
    exec_ = getattr(builtins, 'exec')


__all__ = [
    'StringIO', 'exec_'
]
