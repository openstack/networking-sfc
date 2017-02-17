# Copyright (c) 2016 Huawei Technologies India Pvt.Limited.
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

import logging

from osc_lib.command import command
from osc_lib import utils

from neutronclient._i18n import _
from neutronclient.common import utils as nc_utils

from networking_sfc.osc import common

LOG = logging.getLogger(__name__)

SFC_COMMON_PREFIX = "/sfc"
PORT_CHAIN_PATH = SFC_COMMON_PREFIX + "/port_chains"
resource = 'port_chain'


class CreatePortChain(command.ShowOne):
    """Create a Port Chain."""

    def get_parser(self, prog_name):
        parser = super(CreatePortChain, self).get_parser(prog_name)
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
            required=True,
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
            type=nc_utils.str2dict_type(optional_keys=['correlation',
                                                       'symmetric']),
            help=_('Dictionary of chain parameters. Supports '
                   'correlation=mpls and symmetric=true|false'))
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        attrs = _get_common_attrs(self.app.client_manager, parsed_args)
        obj = common.create_sfc_resource(client, resource, attrs)
        columns = common.get_columns(obj[resource])
        data = utils.get_dict_properties(obj[resource], columns)
        return columns, data


class UpdatePortChain(command.Command):
    """Update Port Chain's information."""

    def get_parser(self, prog_name):
        parser = super(UpdatePortChain, self).get_parser(prog_name)
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
        parser.add_argument(
            'port_chain',
            metavar='PORT-CHAIN',
            help=_("ID or name of the Port Chain to update."))
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        id = common.find_sfc_resource(client,
                                      resource,
                                      parsed_args.port_chain)
        attrs = _get_common_attrs(self.app.client_manager, parsed_args,
                                  is_create=False)
        if parsed_args.no_flow_classifier:
            attrs['flow_classifiers'] = []
        common.update_sfc_resource(client, resource, attrs, id)


class DeletePortChain(command.Command):
    """Delete a given Port Chain."""

    def get_parser(self, prog_name):
        parser = super(DeletePortChain, self).get_parser(prog_name)
        parser.add_argument(
            'port_chain',
            metavar="PORT_CHAIN",
            help=_("ID or name of the Port Chain to delete.")
        )
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        id = common.find_sfc_resource(client,
                                      resource,
                                      parsed_args.port_chain)
        common.delete_sfc_resource(client, resource, id)


class ListPortChain(command.Lister):
    """List Port Chains."""

    def take_action(self, parsed_args):
        data = self.app.client_manager.neutronclient.list_ext(
            collection='port_chains', path=PORT_CHAIN_PATH,
            retrieve_all=True)
        headers = ('ID', 'Name', 'Port Pair Groups', 'Flow Classifiers',
                   'Chain Parameters')
        columns = ('id', 'name', 'port_pair_groups', 'flow_classifiers',
                   'chain_parameters')
        return (headers,
                (utils.get_dict_properties(
                    s, columns,
                ) for s in data['port_chains']))


class ShowPortChain(command.ShowOne):
    """Show information of a given Port Pair Groups."""

    def get_parser(self, prog_name):
        parser = super(ShowPortChain, self).get_parser(prog_name)
        parser.add_argument(
            'port_chain',
            metavar="PORT_CHAIN",
            help=_("ID or name of the Port Chain to display.")
        )
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        id = common.find_sfc_resource(client,
                                      resource,
                                      parsed_args.port_chain)
        obj = common.show_sfc_resource(client, resource, id)
        columns = common.get_columns(obj[resource])
        data = utils.get_dict_properties(obj[resource], columns)
        return columns, data


def _get_common_attrs(client_manager, parsed_args, is_create=True):
    attrs = {}
    if parsed_args.name is not None:
        attrs['name'] = str(parsed_args.name)
    if parsed_args.description is not None:
        attrs['description'] = str(parsed_args.description)
    if ('port_pair_groups' in parsed_args and
            parsed_args.port_pair_groups is not None):
        attrs['port_pair_groups'] = [(common.find_sfc_resource(
                                      client_manager.neutronclient,
                                      'port_pair_group', ppg))
                                     for ppg in parsed_args.port_pair_groups]
    if ('flow_classifiers' in parsed_args and
            parsed_args.flow_classifiers is not None):
        attrs['flow_classifiers'] = [(common.find_sfc_resource(
                                      client_manager.neutronclient,
                                      'flow_classifier', fc))
                                     for fc in parsed_args.flow_classifiers]
    if is_create is True:
        _get_attrs(attrs, parsed_args)
    return attrs


def _get_attrs(attrs, parsed_args):
    if 'chain_parameters' in parsed_args:
        attrs['chain_parameters'] = parsed_args.chain_parameters
