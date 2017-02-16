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

FLOW_CLASSIFIER_RESOURCE = 'flow_classifier'


def get_flowclassifier_id(client, id_or_name):
    return neutronv20.find_resourceid_by_name_or_id(client,
                                                    FLOW_CLASSIFIER_RESOURCE,
                                                    id_or_name)


class FlowClassifier(extension.NeutronClientExtension):
    resource = FLOW_CLASSIFIER_RESOURCE
    resource_plural = '%ss' % resource
    object_path = '/sfc/%s' % resource_plural
    resource_path = '/sfc/%s/%%s' % resource_plural
    versions = ['2.0']


class FlowClassifierCreate(extension.ClientExtensionCreate,
                           FlowClassifier):
    """Create a Flow Classifier."""

    shell_command = 'flow-classifier-create'

    def add_known_arguments(self, parser):
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
            type=utils.str2dict,
            help=_('Dictionary of L7-parameters. Currently, no value is '
                   'supported for this option.'))

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        if parsed_args.logical_source_port:
            body['logical_source_port'] = pp.get_port_id(
                client, parsed_args.logical_source_port)
        if parsed_args.logical_destination_port:
            body['logical_destination_port'] = pp.get_port_id(
                client, parsed_args.logical_destination_port)
        if parsed_args.source_port:
            self._fill_protocol_port_info(body, 'source',
                                          parsed_args.source_port)
        if parsed_args.destination_port:
            self._fill_protocol_port_info(body, 'destination',
                                          parsed_args.destination_port)
        neutronv20.update_dict(parsed_args, body,
                               ['name', 'description', 'protocol',
                                'source_ip_prefix', 'destination_ip_prefix',
                                'ethertype', 'l7_parameters'])
        return {self.resource: body}

    def _fill_protocol_port_info(self, body, port_type, port_val):
        min_port, sep, max_port = port_val.partition(":")
        if not max_port:
            max_port = min_port
        body[port_type + '_port_range_min'] = int(min_port)
        body[port_type + '_port_range_max'] = int(max_port)


class FlowClassifierUpdate(extension.ClientExtensionUpdate,
                           FlowClassifier):
    """Update Flow Classifier information."""

    shell_command = 'flow-classifier-update'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            metavar='NAME',
            help=_('Name of the Flow Classifier.'))
        parser.add_argument(
            '--description',
            help=_('Description for the Flow Classifier.'))

    def args2body(self, parsed_args):
        body = {}
        neutronv20.update_dict(parsed_args, body, ['name', 'description'])
        return {self.resource: body}


class FlowClassifierDelete(extension.ClientExtensionDelete,
                           FlowClassifier):
    """Delete a given Flow Classifier."""

    shell_command = 'flow-classifier-delete'


class FlowClassifierList(extension.ClientExtensionList,
                         FlowClassifier):
    """List Flow Classifiers that belong to a given tenant."""

    shell_command = 'flow-classifier-list'
    list_columns = ['id', 'name', 'summary']
    pagination_support = True
    sorting_support = True

    def extend_list(self, data, parsed_args):
        for d in data:
            val = []
            if d.get('protocol'):
                protocol = d['protocol'].upper()
            else:
                protocol = 'any'
            protocol = 'protocol: ' + protocol
            val.append(protocol)
            val.append(self._get_protocol_port_details(d, 'source'))
            val.append(self._get_protocol_port_details(d, 'destination'))
            if 'logical_source_port' in d:
                val.append('neutron_source_port: ' +
                           str(d['logical_source_port']))

            if 'logical_destination_port' in d:
                val.append('neutron_destination_port: ' +
                           str(d['logical_destination_port']))

            if 'l7_parameters' in d:
                l7_param = 'l7_parameters: {%s}' % ','.join(d['l7_parameters'])
                val.append(l7_param)

            d['summary'] = ',\n'.join(val)

    def _get_protocol_port_details(self, data, type):
        type_ip_prefix = type + '_ip_prefix'
        ip_prefix = data.get(type_ip_prefix)
        if not ip_prefix:
            ip_prefix = 'any'
        min_port = data.get(type + '_port_range_min')
        if min_port is None:
            min_port = 'any'
        max_port = data.get(type + '_port_range_max')
        if max_port is None:
            max_port = 'any'
        return '%s[port]: %s[%s:%s]' % (
            type, ip_prefix, min_port, max_port)


class FlowClassifierShow(extension.ClientExtensionShow, FlowClassifier):
    """Show information of a given Flow Classifier."""

    shell_command = 'flow-classifier-show'
