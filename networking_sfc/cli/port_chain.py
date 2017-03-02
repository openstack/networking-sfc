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
from networking_sfc.cli import flow_classifier as fc
from networking_sfc.cli import port_pair_group as ppg

PORT_CHAIN_RESOURCE = 'port_chain'


class PortChain(extension.NeutronClientExtension):
    resource = PORT_CHAIN_RESOURCE
    resource_plural = '%ss' % resource
    object_path = '/sfc/%s' % resource_plural
    resource_path = '/sfc/%s/%%s' % resource_plural
    versions = ['2.0']


class PortChainCreate(extension.ClientExtensionCreate, PortChain):
    """Create a Port Chain."""

    shell_command = 'port-chain-create'

    def add_known_arguments(self, parser):
        parser.add_argument(
            'name',
            metavar='NAME',
            help=_('Name of the Port Chain.'))
        parser.add_argument(
            '--description',
            help=_('Description for the Port Chain.'))
        parser.add_argument(
            '--port-pair-group',
            metavar='PORT-PAIR-GROUP',
            dest='port_pair_groups',
            default=[], required=True,
            action='append',
            help=_('ID or name of the Port Pair Group. '
                   'This option can be repeated.'))
        parser.add_argument(
            '--flow-classifier',
            default=[],
            metavar='FLOW-CLASSIFIER',
            dest='flow_classifiers',
            action='append',
            help=_('ID or name of the Flow Classifier.'
                   'This option can be repeated.'))
        parser.add_argument(
            '--chain-parameters',
            metavar='[correlation=CORRELATION_TYPE, symmetric=BOOLEAN_TYPE]',
            type=utils.str2dict_type(optional_keys=['correlation',
                                                    'symmetric']),
            help=_('Dictionary of chain parameters. Supports '
                   'correlation=mpls and symmetric=true|false.'))

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        if parsed_args.port_pair_groups:
            body['port_pair_groups'] = [ppg.get_port_pair_group_id(client, p)
                                        for p in parsed_args.port_pair_groups]
        if parsed_args.flow_classifiers:
            body['flow_classifiers'] = [fc.get_flowclassifier_id(client, f)
                                        for f in parsed_args.flow_classifiers]
        neutronv20.update_dict(parsed_args, body, ['name', 'description',
                                                   'chain_parameters'])
        return {self.resource: body}


class PortChainUpdate(extension.ClientExtensionUpdate, PortChain):
    """Update Port Chain's information."""

    shell_command = 'port-chain-update'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            metavar='NAME',
            help=_('Name of the Port Chain.'))
        parser.add_argument(
            '--description',
            help=_('Description for the Port Chain.'))
        fw_args = parser.add_mutually_exclusive_group()
        fw_args.add_argument(
            '--flow-classifier',
            metavar='FLOW-CLASSIFIER',
            dest='flow_classifiers',
            action='append',
            help=_('ID or name of the Flow Classifier. '
                   'This option can be repeated.'))
        fw_args.add_argument(
            '--no-flow-classifier',
            action='store_true',
            help=_('Associate no Flow Classifier with the Port Chain.'))
        parser.add_argument(
            '--port-pair-group',
            metavar='PORT-PAIR-GROUP',
            dest='port_pair_groups',
            action='append',
            help=_('ID or name of the port pair group. '
                    'This option can be repeated.'))

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        if parsed_args.flow_classifiers:
            body['flow_classifiers'] = [fc.get_flowclassifier_id(client, f)
                                        for f in parsed_args.flow_classifiers]
        elif parsed_args.no_flow_classifier:
            body['flow_classifiers'] = []
        if parsed_args.port_pair_groups:
            body['port_pair_groups'] = [ppg.get_port_pair_group_id(client, p)
                                        for p in parsed_args.port_pair_groups]
        neutronv20.update_dict(parsed_args, body, ['name', 'description'])
        return {self.resource: body}


class PortChainDelete(extension.ClientExtensionDelete, PortChain):
    """Delete a given Port Chain."""

    shell_command = 'port-chain-delete'


class PortChainList(extension.ClientExtensionList, PortChain):
    """List Port Chains that belong to a given tenant."""

    shell_command = 'port-chain-list'
    list_columns = ['id', 'name', 'port_pair_groups', 'flow_classifiers']
    pagination_support = True
    sorting_support = True


class PortChainShow(extension.ClientExtensionShow, PortChain):
    """Show information of a given Port Chain."""

    shell_command = 'port-chain-show'
