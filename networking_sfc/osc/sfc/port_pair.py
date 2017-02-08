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
PORT_PAIR_PATH = SFC_COMMON_PREFIX + "/port_pairs"
resource = 'port_pair'


class CreatePortPair(command.ShowOne):
    """Create a Port Pair."""

    def get_parser(self, prog_name):
        parser = super(CreatePortPair, self).get_parser(prog_name)
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
            '--service-function-parameter',
            metavar='[correlation=CORRELATION_TYPE, weight=WEIGHT]',
            type=nc_utils.str2dict_type(optional_keys=['correlation',
                                                       'weight']),
            help=_('Dictionary of Service function parameters. '
                   'Currently, only correlation=None and weight '
                   'is supported. Weight is an integer that influences '
                   'the selection of a port pair within a port pair group '
                   'for a flow. The higher the weight, the more flows will '
                   'hash to the port pair. The default weight is 1.'))
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        attrs = _get_common_attrs(self.app.client_manager, parsed_args)
        obj = common.create_sfc_resource(client, resource, attrs)
        columns = common.get_columns(obj[resource])
        data = utils.get_dict_properties(obj[resource], columns)
        return columns, data


class UpdatePortPair(command.Command):
    """Update Port Pair's information."""

    def get_parser(self, prog_name):
        parser = super(UpdatePortPair, self).get_parser(prog_name)
        parser.add_argument(
            '--name',
            metavar='NAME',
            help=_('Name of the Port Pair.'))
        parser.add_argument(
            '--description',
            help=_('Description for the Port Pair.'))
        parser.add_argument(
            'port_pair',
            metavar="PORT_PAIR",
            help=_("ID or name of the Port Pair to update.")
        )
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        id = common.find_sfc_resource(client,
                                      resource,
                                      parsed_args.port_pair)
        attrs = _get_common_attrs(self.app.client_manager, parsed_args,
                                  is_create=False)
        common.update_sfc_resource(client, resource, attrs, id)


class DeletePortPair(command.Command):
    """Delete a given Port Pair."""

    def get_parser(self, prog_name):
        parser = super(DeletePortPair, self).get_parser(prog_name)
        parser.add_argument(
            'port_pair',
            metavar="PORT_PAIR",
            help=_("ID or name of the Port Pair to delete.")
        )
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        id = common.find_sfc_resource(client,
                                      resource,
                                      parsed_args.port_pair)
        common.delete_sfc_resource(client, resource, id)


class ListPortPair(command.Lister):
    """List Port Pairs."""

    def take_action(self, parsed_args):
        data = self.app.client_manager.neutronclient.list_ext(
            collection='port_pairs', path=PORT_PAIR_PATH,
            retrieve_all=True)
        headers = ('ID', 'Name', 'Ingress Logical Port', 'Egress Logical Port')
        columns = ('id', 'name', 'ingress', 'egress')
        return (headers,
                (utils.get_dict_properties(
                    s, columns,
                ) for s in data['port_pairs']))


class ShowPortPair(command.ShowOne):
    """Show information of a given Port Pair."""

    def get_parser(self, prog_name):
        parser = super(ShowPortPair, self).get_parser(prog_name)
        parser.add_argument(
            'port_pair',
            metavar="PORT_PAIR",
            help=_("ID or name of the Port Pair to display")
        )
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        id = common.find_sfc_resource(client,
                                      resource,
                                      parsed_args.port_pair)
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
    if is_create is True:
        _get_attrs(client_manager, attrs, parsed_args)
    return attrs


def _get_attrs(client_manager, attrs, parsed_args):
    if parsed_args.ingress is not None:
        attrs['ingress'] = common.get_id(client_manager.neutronclient,
                                         parsed_args.ingress,
                                         'port')
    if parsed_args.egress is not None:
        attrs['egress'] = common.get_id(client_manager.neutronclient,
                                        parsed_args.egress,
                                        'port')
    if 'service_function_parameters' in parsed_args:
        attrs['service_function_parameters'] = (
            parsed_args.service_function_parameters)
