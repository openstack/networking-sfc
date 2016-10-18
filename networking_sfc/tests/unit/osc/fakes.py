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
import uuid

from osc_lib.tests import utils


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
            service-function-parameter, tenant_id
        """
        attrs = attrs or {}

        # Set default attributes.
        port_pair_attrs = {
            'id': uuid.uuid4().hex,
            'name': 'port-pair-name',
            'description': 'description',
            'ingress': uuid.uuid4().hex,
            'egress': uuid.uuid4().hex,
            'service_function_parameter': '{weight: 1, correlation: None}',
            'tenant_id': uuid.uuid4().hex,
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
        for i in range(0, count):
            port_pair = port_pairs.append(FakePortPair.create_port_pair(attrs))
        port_pairs.append(port_pair)

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
            port_pair_group_parameters, tenant_id
        """
        attrs = attrs or {}

        # Set default attributes.
        port_pair_group_attrs = {
            'id': uuid.uuid4().hex,
            'group_id': uuid.uuid4().hex,
            'name': 'port-pair-group-name',
            'description': 'description',
            'port_pairs': uuid.uuid4().hex,
            'port_pair_group_parameters': '{"lb_fields": []}',
            'tenant_id': uuid.uuid4().hex,
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
        for i in range(0, count):
            port_pair_group = port_pair_groups.append(
                FakePortPairGroup.create_port_pair_group(attrs))
        port_pair_groups.append(port_pair_group)

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
            'id': uuid.uuid4().hex,
            'destination_ip_prefix': '2.2.2.2/32',
            'destination_port_range_max': '90',
            'destination_port_range_min': '80',
            'ethertype': 'Ipv4',
            'logical_destination_port': uuid.uuid4().hex,
            'logical_source_port': uuid.uuid4().hex,
            'name': 'port-pair-group-name',
            'description': 'fc_description',
            'protocol': 'tcp',
            'source_ip_prefix': '1.1.1.1/32',
            'source_port_range_max': '20',
            'source_port_range_min': '10',
            'tenant_id': uuid.uuid4().hex,
            'l7_parameters': '{}',
            'no_flow_classiifier': 'True'
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
        for i in range(0, count):
            flow_classifier = flow_classifiers.append(
                FakeFlowClassifier.create_flow_classifier(attrs))
        flow_classifiers.append(flow_classifier)

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
            'id': uuid.uuid4().hex,
            'chain_id': uuid.uuid4().hex,
            'name': 'port-pair-group-name',
            'description': 'description',
            'port_pair_groups': uuid.uuid4().hex,
            'flow_classifiers': uuid.uuid4().hex,
            'chain_parameters': '{"correlation": mpls}',
            'tenant_id': uuid.uuid4().hex,
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
        for i in range(0, count):
            port_chain = port_chains.append(
                FakePortChain.create_port_chain(attrs))
        port_chains.append(port_chain)

        return {'port_chains': port_chains}
