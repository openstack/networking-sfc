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

import six

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
            metavar=(
                'type=TYPE[,service_type=SERVICE_TYPE'
                ',lb_fields=LB_FIELDS]'),
            type=utils.str2dict,
            help=_('Dictionary of Port pair group parameters. '
                   'Currently, only service_type=[l2,l3] and '
                   '\'&\' separated string of the lb_fields '
                   'are supported.'))

    def args2body(self, parsed_args):
        body = {}
        if parsed_args.port_pair_group_parameters:
            body['port_pair_group_parameters'] = {}
            for key, value in six.iteritems(
                parsed_args.port_pair_group_parameters
            ):
                if key == 'lb_fields':
                    body['port_pair_group_parameters'][key] = ([
                        field for field in value.split('&') if field])
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
