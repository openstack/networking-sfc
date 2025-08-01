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

import unittest

from networking_sfc.hacking import checks


class TestEventletBan(unittest.TestCase):

    def test_eventlet_import_banned(self):
        """Test that eventlet imports are detected and banned."""
        # Test direct import
        result = checks.check_no_eventlet_import("import eventlet")
        self.assertEqual(next(result),
                         (0, "H999: eventlet must not be imported."))

        # Test from import
        result = checks.check_no_eventlet_import(
            "from eventlet import greenthread")
        self.assertEqual(next(result),
                         (0, "H999: eventlet must not be imported."))

        # Test with whitespace
        result = checks.check_no_eventlet_import("    import eventlet")
        self.assertEqual(next(result),
                         (0, "H999: eventlet must not be imported."))

        result = checks.check_no_eventlet_import(
            "  from eventlet import something")
        self.assertEqual(next(result),
                         (0, "H999: eventlet must not be imported."))

    def test_eventlet_import_variations(self):
        """Test various eventlet import variations."""
        # Test submodule imports
        result = checks.check_no_eventlet_import(
            "from eventlet.green import socket")
        self.assertEqual(next(result),
                         (0, "H999: eventlet must not be imported."))

        result = checks.check_no_eventlet_import(
            "import eventlet.greenthread")
        self.assertEqual(next(result),
                         (0, "H999: eventlet must not be imported."))

    def test_allowed_imports(self):
        """Test that non-eventlet imports are allowed."""
        # Test other imports that should be allowed
        result = checks.check_no_eventlet_import("import os")
        with self.assertRaises(StopIteration):
            next(result)

        result = checks.check_no_eventlet_import(
            "from neutron import context")
        with self.assertRaises(StopIteration):
            next(result)

        result = checks.check_no_eventlet_import("import threading")
        with self.assertRaises(StopIteration):
            next(result)

        # Test imports that contain 'eventlet' but aren't eventlet imports
        result = checks.check_no_eventlet_import("import my_eventlet_utils")
        with self.assertRaises(StopIteration):
            next(result)

        result = checks.check_no_eventlet_import(
            "from some_module import eventlet_func")
        with self.assertRaises(StopIteration):
            next(result)

    def test_comments_and_strings(self):
        """Test that eventlet in comments and strings is ignored."""
        # Comments should be ignored by the logical line processor
        result = checks.check_no_eventlet_import("# This is about eventlet")
        with self.assertRaises(StopIteration):
            next(result)

        # String literals should be ignored
        result = checks.check_no_eventlet_import(
            'print("eventlet is removed")')
        with self.assertRaises(StopIteration):
            next(result)

        result = checks.check_no_eventlet_import(
            "'eventlet import should be banned'")
        with self.assertRaises(StopIteration):
            next(result)
