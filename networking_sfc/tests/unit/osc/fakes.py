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

import argparse
import copy

import mock
from osc_lib.tests import utils
from oslo_utils import uuidutils


class TestNeutronClientOSCV2(utils.TestCommand):

    def setUp(self):
        super(TestNeutronClientOSCV2, self).setUp()
        self.namespace = argparse.Namespace()
        self.app.client_manager.session = mock.Mock()
        self.app.client_manager.neutronclient = mock.Mock()
        self.neutronclient = self.app.client_manager.neutronclient


class FakePortPair(object):
    """Fake port pair attributes."""

    @staticmethod
    def create_port_pair(attrs=None):
        """Create a fake port pair.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A Dictionary with id, name, description, ingress, egress,
            service-function-parameter, project_id
        """
        attrs = attrs or {}

        # Set default attributes.
        port_pair_attrs = {
            'id': uuidutils.generate_uuid(),
            'name': 'port-pair-name',
            'description': 'description',
            'ingress': uuidutils.generate_uuid(),
            'egress': uuidutils.generate_uuid(),
            'service_function_parameter': '{weight: 1, correlation: None}',
            'project_id': uuidutils.generate_uuid(),
        }

        # Overwrite default attributes.
        port_pair_attrs.update(attrs)
        return copy.deepcopy(port_pair_attrs)

    @staticmethod
    def create_port_pairs(attrs=None, count=1):
        """Create multiple port_pairs.

        :param Dictionary attrs:
            A dictionary with all attributes
        :param int count:
            The number of port_pairs to fake
        :return:
            A list of dictionaries faking the port_pairs
        """
        port_pairs = []
        for _ in range(count):
            port_pairs.append(FakePortPair.create_port_pair(attrs))
        return {'port_pairs': port_pairs}


class FakePortPairGroup(object):
    """Fake port pair group attributes."""

    @staticmethod
    def create_port_pair_group(attrs=None):
        """Create a fake port pair group.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A Dictionary with id, name, description, port_pairs, group_id
            port_pair_group_parameters, project_id
        """
        attrs = attrs or {}

        # Set default attributes.
        port_pair_group_attrs = {
            'id': uuidutils.generate_uuid(),
            'group_id': uuidutils.generate_uuid(),
            'name': 'port-pair-group-name',
            'description': 'description',
            'port_pairs': uuidutils.generate_uuid(),
            'port_pair_group_parameters': '{"lb_fields": []}',
            'project_id': uuidutils.generate_uuid(),
        }

        # port_pair_group_attrs default attributes.
        port_pair_group_attrs.update(attrs)
        return copy.deepcopy(port_pair_group_attrs)

    @staticmethod
    def create_port_pair_groups(attrs=None, count=1):
        """Create multiple port pair groups.

        :param Dictionary attrs:
            A dictionary with all attributes
        :param int count:
            The number of port_pair_groups to fake
        :return:
            A list of dictionaries faking the port pair groups
        """
        port_pair_groups = []
        for _ in range(count):
            port_pair_groups.append(
                FakePortPairGroup.create_port_pair_group(attrs))
        return {'port_pair_groups': port_pair_groups}


class FakeFlowClassifier(object):
    """Fake flow classifier attributes."""

    @staticmethod
    def create_flow_classifier(attrs=None):
        """Create a fake flow classifier.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A Dictionary with faking port chain attributes
        """
        attrs = attrs or {}

        # Set default attributes.
        flow_classifier_attrs = {
            'id': uuidutils.generate_uuid(),
            'destination_ip_prefix': '2.2.2.2/32',
            'destination_port_range_max': '90',
            'destination_port_range_min': '80',
            'ethertype': 'Ipv4',
            'logical_destination_port': uuidutils.generate_uuid(),
            'logical_source_port': uuidutils.generate_uuid(),
            'name': 'port-pair-group-name',
            'description': 'fc_description',
            'protocol': 'tcp',
            'source_ip_prefix': '1.1.1.1/32',
            'source_port_range_max': '20',
            'source_port_range_min': '10',
            'project_id': uuidutils.generate_uuid(),
            'l7_parameters': '{}',
            'no_flow_classifier': 'True'
        }

        flow_classifier_attrs.update(attrs)
        return copy.deepcopy(flow_classifier_attrs)

    @staticmethod
    def create_flow_classifiers(attrs=None, count=1):
        """Create multiple flow classifiers.

        :param Dictionary attrs:
            A dictionary with all attributes
        :param int count:
            The number of flow classifiers to fake
        :return:
            A list of dictionaries faking the flow classifiers
        """
        flow_classifiers = []
        for _ in range(count):
            flow_classifiers.append(
                FakeFlowClassifier.create_flow_classifier(attrs))
        return {'flow_classifiers': flow_classifiers}


class FakePortChain(object):
    """Fake port chain attributes."""

    @staticmethod
    def create_port_chain(attrs=None):
        """Create a fake port chain.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A Dictionary with faking port chain attributes
        """
        attrs = attrs or {}

        # Set default attributes.
        port_chain_attrs = {
            'id': uuidutils.generate_uuid(),
            'chain_id': uuidutils.generate_uuid(),
            'name': 'port-pair-group-name',
            'description': 'description',
            'port_pair_groups': uuidutils.generate_uuid(),
            'flow_classifiers': uuidutils.generate_uuid(),
            'chain_parameters': '{"correlation": mpls}',
            'project_id': uuidutils.generate_uuid(),
        }

        # port_pair_group_attrs default attributes.
        port_chain_attrs.update(attrs)
        return copy.deepcopy(port_chain_attrs)

    @staticmethod
    def create_port_chains(attrs=None, count=1):
        """Create multiple port chains.

        :param Dictionary attrs:
            A dictionary with all attributes
        :param int count:
            The number of port chains to fake
        :return:
            A list of dictionaries faking the port chains.
        """
        port_chains = []
        for _ in range(count):
            port_chains.append(FakePortChain.create_port_chain(attrs))
        return {'port_chains': port_chains}
