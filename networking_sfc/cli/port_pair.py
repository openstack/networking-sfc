# Copyright (c) 2015 Huawei Technologies India Pvt.Limited.
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

from neutronclient.common import extension
from neutronclient.common import utils
from neutronclient.neutron import v2_0 as neutronv20

from networking_sfc._i18n import _

PORT_RESOURCE = 'port'
PORT_PAIR_RESOURCE = 'port_pair'


def get_port_id(client, id_or_name):
    return neutronv20.find_resourceid_by_name_or_id(client,
                                                    PORT_RESOURCE,
                                                    id_or_name)


def get_port_pair_id(client, id_or_name):
    return neutronv20.find_resourceid_by_name_or_id(client,
                                                    PORT_PAIR_RESOURCE,
                                                    id_or_name)


class PortPair(extension.NeutronClientExtension):
    resource = PORT_PAIR_RESOURCE
    resource_plural = '%ss' % resource
    object_path = '/sfc/%s' % resource_plural
    resource_path = '/sfc/%s/%%s' % resource_plural
    versions = ['2.0']


class PortPairCreate(extension.ClientExtensionCreate, PortPair):
    """Create a Port Pair."""

    shell_command = 'port-pair-create'

    def add_known_arguments(self, parser):
        parser.add_argument(
            'name',
            metavar='NAME',
            help=_('Name of the Port Pair.'))
        parser.add_argument(
            '--description',
            help=_('Description for the Port Pair.'))
        parser.add_argument(
            '--ingress',
            required=True,
            help=_('ID or name of the ingress neutron port.'))
        parser.add_argument(
            '--egress',
            required=True,
            help=_('ID or name of the egress neutron port.'))
        parser.add_argument(
            '--service-function-parameters',
            metavar='[correlation=CORRELATION_TYPE, weight=WEIGHT]',
            type=utils.str2dict_type(optional_keys=['correlation',
                                                    'weight']),
            help=_('Dictionary of Service function parameters. '
                   'Currently, only correlation=None|mpls and weight '
                   'is supported. Default correlation is None. Weight is '
                   'an integer that influences the selection'
                   'of a port pair within a port pair group '
                   'for a flow. The higher the weight, the more flows will '
                   'hash to the port pair. The default weight is 1.'))

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        if parsed_args.ingress:
            body['ingress'] = get_port_id(client, parsed_args.ingress)
        if parsed_args.egress:
            body['egress'] = get_port_id(client, parsed_args.egress)
        neutronv20.update_dict(parsed_args, body,
                               ['name', 'description',
                                'service_function_parameters'])
        return {self.resource: body}


class PortPairUpdate(extension.ClientExtensionUpdate, PortPair):
    """Update Port Pair's information."""

    shell_command = 'port-pair-update'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            metavar='NAME',
            help=_('Name of the Port Pair.'))
        parser.add_argument(
            '--description',
            help=_('Description for the Port Pair.'))

    def args2body(self, parsed_args):
        body = {}
        neutronv20.update_dict(parsed_args, body, ['name', 'description'])
        return {self.resource: body}


class PortPairDelete(extension.ClientExtensionDelete, PortPair):
    """Delete a given Port Pair."""

    shell_command = 'port-pair-delete'


class PortPairList(extension.ClientExtensionList, PortPair):
    """List Port Pairs that belongs to a given tenant."""

    shell_command = 'port-pair-list'
    list_columns = ['id', 'name', 'ingress', 'egress']
    pagination_support = True
    sorting_support = True


class PortPairShow(extension.ClientExtensionShow, PortPair):
    """Show information of a given Port Pair."""

    shell_command = 'port-pair-show'
