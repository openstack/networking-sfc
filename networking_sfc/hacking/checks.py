# Copyright 2025 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import re

from hacking import core


# Regular expression to match eventlet imports
EVENTLET_IMPORT_RE = re.compile(r'^\s*(import|from)\s+eventlet')


@core.flake8ext
def check_no_eventlet_import(logical_line):
    """Check that eventlet is not imported.

    Eventlet has been removed from the project and should not be reintroduced.
    This check prevents accidental reintroduction of eventlet imports.

    H999 - eventlet must not be imported.
    """
    if EVENTLET_IMPORT_RE.search(logical_line):
        yield 0, "H999: eventlet must not be imported."


def factory(register):
    """Register custom hacking checks."""
    register(check_no_eventlet_import)
