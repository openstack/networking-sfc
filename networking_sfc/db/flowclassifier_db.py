# Copyright 2015 Futurewei.  All rights reserved.
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

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import uuidutils

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm.collections import attribute_mapped_collection
from sqlalchemy.orm import exc

from neutron.common import constants as const
from neutron.db import common_db_mixin
from neutron.db import model_base
from neutron.db import models_v2
from neutron.i18n import _LI

from networking_sfc.extensions import flowclassifier as fc_ext

LOG = logging.getLogger(__name__)


class L7Parameter(model_base.BASEV2):
    """Represents a L7 parameter."""
    __tablename__ = 'sfc_flow_classifier_l7_parameters'
    keyword = sa.Column(sa.String(255), primary_key=True)
    value = sa.Column(sa.String(255))
    classifier_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('sfc_flow_classifiers.id', ondelete='CASCADE'),
        primary_key=True)


class FlowClassifier(model_base.BASEV2, models_v2.HasId,
                     models_v2.HasTenant):
    """Represents a v2 neutron flow classifier."""
    __tablename__ = 'sfc_flow_classifiers'

    name = sa.Column(sa.String(255))
    ethertype = sa.Column(sa.String(40))
    protocol = sa.Column(sa.String(40))
    description = sa.Column(sa.String(255))
    source_port_range_min = sa.Column(sa.Integer)
    source_port_range_max = sa.Column(sa.Integer)
    destination_port_range_min = sa.Column(sa.Integer)
    destination_port_range_max = sa.Column(sa.Integer)
    source_ip_prefix = sa.Column(sa.String(255))
    destination_ip_prefix = sa.Column(sa.String(255))
    l7_parameters = orm.relationship(
        L7Parameter,
        collection_class=attribute_mapped_collection('keyword'),
        cascade='all, delete-orphan')


class FlowClassifierDbPlugin(fc_ext.FlowClassifierPluginBase,
                             common_db_mixin.CommonDbMixin):

    def _check_port_range_valid(self, port_range_min,
                                port_range_max,
                                protocol):
        if (
            port_range_min is not None and
            port_range_max is not None and
            port_range_min > port_range_max
        ):
            raise fc_ext.FlowClassifierInvalidPortRange(
                port_range_min=port_range_min,
                port_range_max=port_range_max
            )
        if port_range_min is not None or port_range_max is not None:
            if protocol not in [const.PROTO_NAME_TCP, const.PROTO_NAME_UDP]:
                raise fc_ext.FlowClassifierProtocolRequiredWithPorts()

    def _get_fixed_ip_from_port(self, context, logical_port, ip_prefix):
        if logical_port is not None:
            self._get_port(context, logical_port)
        return ip_prefix

    @log_helpers.log_method_call
    def create_flow_classifier(self, context, flow_classifier):
        fc = flow_classifier['flow_classifier']
        tenant_id = self._get_tenant_id_for_create(context, fc)
        l7_parameters = {
            key: L7Parameter(key, val)
            for key, val in six.iteritems(fc['l7_parameters'])}
        source_port_range_min = fc['source_port_range_min']
        source_port_range_max = fc['source_port_range_max']

        self._check_port_range_valid(source_port_range_min,
                                     source_port_range_max,
                                     fc['protocol'])
        destination_port_range_min = fc['destination_port_range_min']
        destination_port_range_max = fc['destination_port_range_max']
        self._check_port_range_valid(destination_port_range_min,
                                     destination_port_range_max,
                                     fc['protocol'])
        source_ip_prefix = fc['source_ip_prefix']
        destination_ip_prefix = fc['destination_ip_prefix']

        logical_source_port = fc['logical_source_port']
        logical_destination_port = fc['logical_destination_port']
        with context.session.begin(subtransactions=True):
            source_ip_prefix = self._get_fixed_ip_from_port(
                context, logical_source_port, source_ip_prefix)
            destination_ip_prefix = self._get_fixed_ip_from_port(
                context, logical_destination_port, destination_ip_prefix)
            flow_classifier_db = FlowClassifier(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=fc['name'],
                description=fc['description'],
                ethertype=fc['ethertype'],
                protocol=fc['protocol'],
                source_port_range_min=source_port_range_min,
                source_port_range_max=source_port_range_max,
                destination_port_range_min=destination_port_range_min,
                destination_port_range_max=destination_port_range_max,
                source_ip_prefix=source_ip_prefix,
                destination_ip_prefix=destination_ip_prefix,
                l7_parameters=l7_parameters
            )
            context.session.add(flow_classifier_db)
            return self._make_flow_classifier_dict(flow_classifier_db)

    def _make_flow_classifier_dict(self, flow_classifier, fields=None):
        res = {
            'id': flow_classifier['id'],
            'name': flow_classifier['name'],
            'description': flow_classifier['description'],
            'tenant_id': flow_classifier['tenant_id'],
            'ethertype': flow_classifier['ethertype'],
            'protocol': flow_classifier['protocol'],
            'source_port_range_min': flow_classifier['source_port_range_min'],
            'source_port_range_max': flow_classifier['source_port_range_max'],
            'destination_port_range_min': (
                flow_classifier['destination_port_range_min']),
            'destination_port_range_max': (
                flow_classifier['destination_port_range_max']),
            'source_ip_prefix': flow_classifier['source_ip_prefix'],
            'destination_ip_prefix': flow_classifier['destination_ip_prefix'],
            'l7_parameters': {
                param['keyword']: param['value']
                for k, param in six.iteritems(flow_classifier.l7_parameters)
            }

        }
        return self._fields(res, fields)

    @log_helpers.log_method_call
    def get_flow_classifiers(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'flow_classifier',
                                          limit, marker)
        return self._get_collection(context,
                                    FlowClassifier,
                                    self._make_flow_classifier_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit, marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log_helpers.log_method_call
    def get_flow_classifier(self, context, id, fields=None):
        flow_classifier = self._get_flow_classifier(context, id)
        return self._make_flow_classifier_dict(flow_classifier, fields)

    def _get_flow_classifier(self, context, id):
        try:
            return self._get_by_id(context, FlowClassifier, id)
        except exc.NoResultFound:
            raise fc_ext.FlowClassifierNotFound(id=id)

    def _get_port(self, context, id):
        try:
            return self._get_by_id(context, models_v2.Port, id)
        except exc.NoResultFound:
            raise fc_ext.FlowClassifierPortNotFound(id=id)

    @log_helpers.log_method_call
    def update_flow_classifier(self, context, id, flow_classifier):
        new_fc = flow_classifier['flow_classifier']
        with context.session.begin(subtransactions=True):
            old_fc = self._get_flow_classifier(context, id)
            old_fc.update(new_fc)
            return self._make_flow_classifier_dict(old_fc)

    @log_helpers.log_method_call
    def delete_flow_classifier(self, context, id):
        try:
            with context.session.begin(subtransactions=True):
                fc = self._get_flow_classifier(context, id)
                context.session.delete(fc)
        except AssertionError:
            raise fc_ext.FlowClassifierInUse(id=id)
        except fc_ext.FlowClassifierNotFound:
            LOG.info(_LI("Deleting a non-existing flow classifier."))
