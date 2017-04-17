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
from networking_sfc.cli import port_pair as pp

PORT_PAIR_GROUP_RESOURCE = 'port_pair_group'


def get_port_pair_group_id(client, id_or_name):
    return neutronv20.find_resourceid_by_name_or_id(client,
                                                    PORT_PAIR_GROUP_RESOURCE,
                                                    id_or_name)


class PortPairGroup(extension.NeutronClientExtension):
    resource = PORT_PAIR_GROUP_RESOURCE
    resource_plural = '%ss' % resource
    object_path = '/sfc/%s' % resource_plural
    resource_path = '/sfc/%s/%%s' % resource_plural
    versions = ['2.0']


def add_common_arguments(parser):
    parser.add_argument(
        '--description',
        help=_('Description for the Port Pair Group.'))
    parser.add_argument(
        '--port-pair',
        metavar='PORT-PAIR',
        dest='port_pairs',
        default=[],
        action='append',
        help=_('ID or name of the Port Pair. '
               'This option can be repeated.'))


def update_common_args2body(client, body, parsed_args):
    if parsed_args.port_pairs:
        body['port_pairs'] = [(pp.get_port_pair_id(client, pp1))
                              for pp1 in parsed_args.port_pairs]
    neutronv20.update_dict(parsed_args, body, ['name', 'description'])
    return body


class PortPairGroupCreate(extension.ClientExtensionCreate, PortPairGroup):
    """Create a Port Pair Group."""
    shell_command = 'port-pair-group-create'

    def add_known_arguments(self, parser):
        parser.add_argument(
            'name',
            metavar='NAME',
            help=_('Name of the Port Pair Group.'))
        add_common_arguments(parser)
        parser.add_argument(
            '--port-pair-group-parameters',
            metavar='[lb_fields=LB_FIELDS, ppg_n_tuple_mapping=TUPLE_VALUES]',
            type=utils.str2dict_type(optional_keys=['lb_fields',
                                                    'ppg_n_tuple_mapping']),
            help=_('Dictionary of Port pair group parameters. '
                   'Currently, only \'&\' separated string of the lb_fields '
                   'and ppg_n_tuple_mapping are supported. For '
                   'ppg_n_tuple_mapping the supported command is '
                   '\'key=value\' separated by \'&\'. Support '
                   'ppg_n_tuple_mapping keys are: source_ip_prefix_ingress, '
                   'source_ip_prefix_egress, destination_ip_prefix_ingress, '
                   'destination_ip_prefix_egress, source_port_ingress, '
                   'source_port_egress, destination_port_ingress, '
                   'destination_port_egress.'))

    def args2body(self, parsed_args):
        body = {}
        if parsed_args.port_pair_group_parameters:
            body['port_pair_group_parameters'] = {}
            for key, value in parsed_args.port_pair_group_parameters.items():
                # Setup lb_fields key and value(s)
                if key == 'lb_fields':
                    body['port_pair_group_parameters'][key] = ([
                        field for field in value.split('&') if field])
                # Setup ppg_n_tuple_mapping key(s) and value(s)
                elif key == 'ppg_n_tuple_mapping':
                    # Reorganize ppg_n_tuple_mapping values in dict with
                    # structure {'ppg_n_tuple_mapping': 'ingress_n_tuple': {},
                    # 'egress_n_tuple': {}}
                    ppg_n_tuple_dict = {}
                    ingress_n_tuple_dict = {}
                    egress_n_tuple_dict = {}
                    # Split input of ppg_n_tuple_mapping by & and =
                    raw_data = dict([
                        (content[0], content[1]) for content in
                        [sub_field.split('=') for sub_field in
                         [field for field in value.split('&') if field]]
                    ])
                    # Store ingress_n_tuple values and egress_n_tuple values
                    # into corresponding dictionary, and expand
                    # source_port_range and destination_port_range to
                    # source_port_range_min, source_port_range_max,
                    # destination_port_range_min, and
                    # destination_port_range_max if exits
                    for n_tuple_key, n_tuple_value in raw_data.items():
                        if n_tuple_key[-7:] == "ingress":
                            n_tuple_key = n_tuple_key[:-8]
                            if (
                                'source_port' in n_tuple_key or
                                'destination_port' in n_tuple_key
                            ):
                                min_port, sep, max_port = \
                                    n_tuple_value.partition(":")
                                if not max_port:
                                    max_port = min_port
                                ingress_n_tuple_dict[
                                    n_tuple_key + '_range_min'] = int(min_port)
                                ingress_n_tuple_dict[
                                    n_tuple_key + '_range_max'] = int(max_port)
                            else:
                                ingress_n_tuple_dict[n_tuple_key] = \
                                    n_tuple_value
                        elif n_tuple_key[-6:] == "egress":
                            n_tuple_key = n_tuple_key[:-7]
                            if (
                                'source_port' in n_tuple_key or
                                'destination_port' in n_tuple_key
                            ):
                                min_port, sep, max_port = \
                                    n_tuple_value.partition(":")
                                if not max_port:
                                    max_port = min_port
                                egress_n_tuple_dict[
                                    n_tuple_key + '_range_min'] = int(min_port)
                                egress_n_tuple_dict[
                                    n_tuple_key + '_range_max'] = int(max_port)
                            else:
                                egress_n_tuple_dict[n_tuple_key] = \
                                    n_tuple_value

                    ppg_n_tuple_dict['ingress_n_tuple'] = ingress_n_tuple_dict
                    ppg_n_tuple_dict['egress_n_tuple'] = egress_n_tuple_dict

                    body['port_pair_group_parameters'][key] = ppg_n_tuple_dict
                else:
                    body['port_pair_group_parameters'][key] = value

        body = update_common_args2body(self.get_client(), body, parsed_args)
        return {self.resource: body}


class PortPairGroupUpdate(extension.ClientExtensionUpdate, PortPairGroup):
    """Update Port Pair Group's information."""

    shell_command = 'port-pair-group-update'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            metavar='NAME',
            help=_('Name of the Port Pair Group.'))
        add_common_arguments(parser)

    def args2body(self, parsed_args):
        body = {}
        body = update_common_args2body(self.get_client(), body, parsed_args)
        return {self.resource: body}


class PortPairGroupDelete(extension.ClientExtensionDelete, PortPairGroup):
    """Delete a given Port Pair Group."""

    shell_command = 'port-pair-group-delete'


class PortPairGroupList(extension.ClientExtensionList, PortPairGroup):
    """List Port Pair Groups that belongs to a given tenant."""

    shell_command = 'port-pair-group-list'
    list_columns = ['id', 'name', 'port_pairs']
    pagination_support = True
    sorting_support = True


class PortPairGroupShow(extension.ClientExtensionShow, PortPairGroup):
    """Show information of a given Port Pair Group."""

    shell_command = 'port-pair-group-show'
