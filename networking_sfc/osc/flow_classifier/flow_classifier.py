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


from osc_lib.command import command
from osc_lib import utils

from neutronclient.common import utils as nc_utils

from networking_sfc._i18n import _
from networking_sfc.osc import common


SFC_COMMON_PREFIX = "/sfc"
FLOW_CLASSIFIERS_PATH = SFC_COMMON_PREFIX + "/flow_classifiers"
resource = 'flow_classifier'


class CreateFlowClassifier(command.ShowOne):
    """Create an Flow Classifier."""

    def get_parser(self, prog_name):
        parser = super(CreateFlowClassifier, self).get_parser(prog_name)
        parser.add_argument(
            'name',
            metavar='NAME',
            help=_('Name of the Flow Classifier.'))
        parser.add_argument(
            '--description',
            help=_('Description for the Flow Classifier.'))
        parser.add_argument(
            '--protocol',
            help=_('IP protocol name. Protocol name should be as per '
                   'IANA standard.'))
        parser.add_argument(
            '--ethertype',
            default='IPv4', choices=['IPv4', 'IPv6'],
            help=_('L2 ethertype, default is IPv4.'))
        parser.add_argument(
            '--source-port',
            help=_('Source protocol port (allowed range [1,65535]. Must be '
                   'specified as a:b, where a=min-port and b=max-port.)'))
        parser.add_argument(
            '--destination-port',
            help=_('Destination protocol port (allowed range [1,65535]. Must '
                   'be specified as a:b, where a=min-port and b=max-port.)'))
        parser.add_argument(
            '--source-ip-prefix',
            help=_('Source IP prefix or subnet.'))
        parser.add_argument(
            '--destination-ip-prefix',
            help=_('Destination IP prefix or subnet.'))
        parser.add_argument(
            '--logical-source-port',
            help=_('ID or name of the neutron source port.'))
        parser.add_argument(
            '--logical-destination-port',
            help=_('ID or name of the neutron destination port.'))
        parser.add_argument(
            '--l7-parameters',
            metavar='type=TYPE[,url=URL_PATH]',
            type=nc_utils.str2dict,
            help=_('Dictionary of L7-parameters. Currently, no value is '
                   'supported for this option.'))

        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        attrs = _get_common_attrs(self.app.client_manager, parsed_args)
        obj = common.create_sfc_resource(client, resource, attrs)
        columns = common.get_columns(obj[resource])
        data = utils.get_dict_properties(obj[resource], columns)
        return columns, data


class UpdateFlowClassifier(command.Command):
    """Update Flow Classifier information."""

    def get_parser(self, prog_name):
        parser = super(UpdateFlowClassifier, self).get_parser(prog_name)
        parser.add_argument(
            '--name',
            metavar='NAME',
            help=_('Name of the Flow Classifier.'))
        parser.add_argument(
            '--description',
            help=_('Description for the Flow Classifier.'))
        parser.add_argument(
            'flow_classifier',
            metavar="FLOW_CLASSIFIER",
            help=_("ID or name of the Flow Classifier to update.")
        )
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        id = common.find_sfc_resource(client,
                                      resource,
                                      parsed_args.flow_classifier)
        attrs = _get_common_attrs(self.app.client_manager, parsed_args,
                                  is_create=False)
        common.update_sfc_resource(client, resource, attrs, id)


class DeleteFlowClassifier(command.Command):
    """Delete a given Flow Classifier."""

    def get_parser(self, prog_name):
        parser = super(DeleteFlowClassifier, self).get_parser(prog_name)
        parser.add_argument(
            'flow_classifier',
            metavar="FLOW_CLASSIFIER",
            help=_("ID or name of the Flow Classifier to delete.")
        )
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        id = common.find_sfc_resource(client,
                                      resource,
                                      parsed_args.flow_classifier)
        common.delete_sfc_resource(client, resource, id)


class ListFlowClassifier(command.Lister):
    """List Flow Classifiers."""

    def take_action(self, parsed_args):
        data = self.app.client_manager.neutronclient.list_ext(
            collection='flow_classifiers', path=FLOW_CLASSIFIERS_PATH,
            retrieve_all=True)
        headers = ('ID', 'Name', 'Protocol', 'Source-IP', 'Destination-IP',
                   'Logical-Source-Port', 'Logical-Destination-Port')
        columns = ('id', 'name', 'protocol', 'source_ip_prefix',
                   'destination_ip_prefix', 'logical_source_port',
                   'logical_destination_port')
        return (headers,
                (utils.get_dict_properties(
                    s, columns,
                ) for s in data['flow_classifiers']))


class ShowFlowClassifier(command.ShowOne):
    """Show information of a given Flow Classifier."""

    def get_parser(self, prog_name):
        parser = super(ShowFlowClassifier, self).get_parser(prog_name)
        parser.add_argument(
            'flow_classifier',
            metavar="FLOW_CLASSIFIER",
            help=_(" ID or name of the Flow Classifier to display.")
        )
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        id = common.find_sfc_resource(client,
                                      resource,
                                      parsed_args.flow_classifier)
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
    if parsed_args.protocol is not None:
        attrs['protocol'] = parsed_args.protocol
    if parsed_args.ethertype:
        attrs['ethertype'] = parsed_args.ethertype
    if parsed_args.source_ip_prefix is not None:
        attrs['source_ip_prefix'] = parsed_args.source_ip_prefix
    if parsed_args.destination_ip_prefix is not None:
        attrs['destination_ip_prefix'] = parsed_args.destination_ip_prefix
    if parsed_args.logical_source_port is not None:
        attrs['logical_source_port'] = common.get_id(
            client_manager.neutronclient, parsed_args.logical_source_port,
            'port')
    if parsed_args.logical_destination_port is not None:
        attrs['logical_destination_port'] = common.get_id(
            client_manager.neutronclient, parsed_args.logical_destination_port,
            'port')
    if parsed_args.source_port is not None:
        _fill_protocol_port_info(attrs, 'source',
                                        parsed_args.source_port)
    if parsed_args.destination_port is not None:
        _fill_protocol_port_info(attrs, 'destination',
                                        parsed_args.destination_port)
    if parsed_args.l7_parameters is not None:
        attrs['l7_parameters'] = parsed_args.l7_parameters


def _fill_protocol_port_info(attrs, port_type, port_val):
        min_port, sep, max_port = port_val.partition(":")
        if not max_port:
            max_port = min_port
        attrs[port_type + '_port_range_min'] = int(min_port)
        attrs[port_type + '_port_range_max'] = int(max_port)
