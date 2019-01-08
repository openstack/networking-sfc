# Copyright (c) 2017 One Convergence Inc
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron_lib.api import converters as lib_converters
from neutron_lib.api import extensions
from neutron_lib import exceptions as neutron_exc

from networking_sfc._i18n import _
from networking_sfc.extensions import sfc

DEFAULT_TAP_ENABLED = False
TAP_EXT = "networking-sfc-tap"


class MultiplePortPairsInTapPPGNotSupported(neutron_exc.InvalidInput):
    """Multiple Port Pairs in Tap PPG not allowed"""
    message = _("Multiple port pairs in Tap port-pair-group is not allowed.")


class ConsecutiveTapPPGNotSupported(neutron_exc.InvalidInput):
    """Unsupported Tap deployment"""
    message = _("Consecutive Tap PPG in port-chain is not supported now.")


EXTENDED_ATTRIBUTES_2_0 = {
    'port_pair_groups': {
        'tap_enabled': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': DEFAULT_TAP_ENABLED,
            'convert_to': lib_converters.convert_to_boolean
        }
    }
}


class Tap(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Networking SFC Passive Tap Service Function support"

    @classmethod
    def get_alias(cls):
        return TAP_EXT

    @classmethod
    def get_description(cls):
        return "Extension for Passive TAP Service Function support"

    @classmethod
    def get_updated(cls):
        return "2017-10-20T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

    @classmethod
    def get_plugin_interface(cls):
        return sfc.SfcPluginBase
