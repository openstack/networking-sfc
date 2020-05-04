from neutron.common import eventlet_utils
eventlet_utils.monkey_patch()
# Monkey patch the original current_thread to use the up-to-date _active
# global variable. See https://bugs.launchpad.net/bugs/1863021 and
# https://github.com/eventlet/eventlet/issues/592
import __original_module_threading as orig_threading  # noqa pylint: disable=wrong-import-position
import threading  # noqa pylint: disable=wrong-import-position,wrong-import-order
orig_threading.current_thread.__globals__['_active'] = threading._active
