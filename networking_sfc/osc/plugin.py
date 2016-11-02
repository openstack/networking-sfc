# Copyright (c) 2016 Huawei Technologies India Pvt.Limited.
# All Rights Reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

import logging

from osc_lib import utils

LOG = logging.getLogger(__name__)

DEFAULT_API_VERSION = '2.0'
API_VERSION_OPTION = 'os_network_api_version'

API_NAME = 'neutronclient'
API_VERSIONS = {
    '2.0': 'neutronclient.v2_0.client.Client',
    '2': 'neutronclient.v2_0.client.Client',
}


def make_client(instance):
    """Returns a neutron client."""
    neutron_client = utils.get_client_class(
        API_NAME,
        instance._api_version[API_NAME],
        API_VERSIONS)
    LOG.debug('Instantiating neutron client: %s', neutron_client)

    client = neutron_client(session=instance.session,
                            region_name=instance._region_name,
                            endpoint_type=instance._interface,
                            insecure=instance._insecure,
                            ca_cert=instance._cacert)
    return client


def build_option_parser(parser):
    """Hook to add global options"""

    return parser
