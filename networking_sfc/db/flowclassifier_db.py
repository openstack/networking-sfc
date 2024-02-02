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

import netaddr

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import uuidutils

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm.collections import attribute_mapped_collection
from sqlalchemy.orm import exc

from neutron_lib import constants as const
from neutron_lib.db import api as db_api
from neutron_lib.db import model_base
from neutron_lib.db import model_query
from neutron_lib.db import utils as db_utils

from neutron.db import models_v2

from networking_sfc.extensions import flowclassifier as fc_ext

LOG = logging.getLogger(__name__)
UUID_LEN = 36


class L7Parameter(model_base.BASEV2):
    """Represents a L7 parameter."""
    __tablename__ = 'sfc_flow_classifier_l7_parameters'
    keyword = sa.Column(sa.String(255), primary_key=True)
    value = sa.Column(sa.String(255))
    classifier_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('sfc_flow_classifiers.id', ondelete='CASCADE'),
        primary_key=True)


class FlowClassifier(model_base.BASEV2, model_base.HasId,
                     model_base.HasProject):
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
    logical_source_port = sa.Column(
        sa.String(UUID_LEN),
        sa.ForeignKey('ports.id', ondelete='RESTRICT'))
    logical_destination_port = sa.Column(
        sa.String(UUID_LEN),
        sa.ForeignKey('ports.id', ondelete='RESTRICT'))
    l7_parameters = orm.relationship(
        L7Parameter,
        collection_class=attribute_mapped_collection('keyword'),
        cascade='all, delete-orphan')


class FlowClassifierDbPlugin(fc_ext.FlowClassifierPluginBase):

    @classmethod
    def _check_port_range_valid(cls, port_range_min,
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

    @classmethod
    def _check_ip_prefix_valid(cls, ip_prefix, ethertype):
        if ip_prefix is not None:
            ip = netaddr.IPNetwork(ip_prefix)
            if ethertype == 'IPv4' and ip.version == 4:
                pass
            elif ethertype == 'IPv6' and ip.version == 6:
                pass
            else:
                raise (
                    fc_ext.FlowClassifierIpPrefixFormatConflictWithEthertype(
                        ip_prefix=ip_prefix, ethertype=ethertype
                    )
                )

    @classmethod
    def _logical_port_conflict(cls, first_logical_port, second_logical_port):
        if first_logical_port is None or second_logical_port is None:
            return True
        return first_logical_port == second_logical_port

    @classmethod
    def _ip_prefix_conflict(cls, first_ip_prefix, second_ip_prefix):
        if first_ip_prefix is None or second_ip_prefix is None:
            return True
        first_ipset = netaddr.IPSet([first_ip_prefix])
        second_ipset = netaddr.IPSet([second_ip_prefix])
        return bool(first_ipset & second_ipset)

    @classmethod
    def _port_range_conflict(
        cls, first_port_range_min, first_port_range_max,
        second_port_range_min, second_port_range_max
    ):
        first_conflict = True
        second_conflict = True
        if (
            first_port_range_min is not None and
            second_port_range_max is not None
        ):
            first_conflict = first_port_range_min <= second_port_range_max
        if (
            first_port_range_max is not None and
            second_port_range_min is not None
        ):
            second_conflict = second_port_range_min <= first_port_range_max
        return first_conflict & second_conflict

    @classmethod
    def _protocol_conflict(cls, first_protocol, second_protocol):
        if first_protocol is None or second_protocol is None:
            return True
        return first_protocol == second_protocol

    @classmethod
    def _ethertype_conflict(cls, first_ethertype, second_ethertype):
        return first_ethertype == second_ethertype

    @classmethod
    def flowclassifier_basic_conflict(
        cls, first_flowclassifier, second_flowclassifier
    ):
        return all([
            cls._ethertype_conflict(
                first_flowclassifier['ethertype'],
                second_flowclassifier['ethertype']
            ),
            cls._protocol_conflict(
                first_flowclassifier['protocol'],
                second_flowclassifier['protocol']
            ),
            cls._ip_prefix_conflict(
                first_flowclassifier['source_ip_prefix'],
                second_flowclassifier['source_ip_prefix']
            ),
            cls._ip_prefix_conflict(
                first_flowclassifier['destination_ip_prefix'],
                second_flowclassifier['destination_ip_prefix']
            ),
            cls._port_range_conflict(
                first_flowclassifier['source_port_range_min'],
                first_flowclassifier['source_port_range_max'],
                second_flowclassifier['source_port_range_min'],
                second_flowclassifier['source_port_range_max']
            ),
            cls._port_range_conflict(
                first_flowclassifier['destination_port_range_min'],
                first_flowclassifier['destination_port_range_max'],
                second_flowclassifier['destination_port_range_min'],
                second_flowclassifier['destination_port_range_max']
            )
        ])

    @classmethod
    def flowclassifier_conflict(
        cls, first_flowclassifier, second_flowclassifier
    ):
        return all([
            cls.flowclassifier_basic_conflict(
                first_flowclassifier,
                second_flowclassifier
            ),
            cls._logical_port_conflict(
                first_flowclassifier['logical_source_port'],
                second_flowclassifier['logical_source_port']
            ),
            cls._logical_port_conflict(
                first_flowclassifier['logical_destination_port'],
                second_flowclassifier['logical_destination_port']
            )
        ])

    @log_helpers.log_method_call
    def create_flow_classifier(self, context, flow_classifier):
        fc = flow_classifier['flow_classifier']
        project_id = fc['project_id']
        l7_parameters = {
            key: L7Parameter(key, val)
            for key, val in fc['l7_parameters'].items()}
        ethertype = fc['ethertype']
        protocol = fc['protocol']
        source_port_range_min = fc['source_port_range_min']
        source_port_range_max = fc['source_port_range_max']
        self._check_port_range_valid(source_port_range_min,
                                     source_port_range_max,
                                     protocol)
        destination_port_range_min = fc['destination_port_range_min']
        destination_port_range_max = fc['destination_port_range_max']
        self._check_port_range_valid(destination_port_range_min,
                                     destination_port_range_max,
                                     protocol)
        source_ip_prefix = fc['source_ip_prefix']
        self._check_ip_prefix_valid(source_ip_prefix, ethertype)
        destination_ip_prefix = fc['destination_ip_prefix']
        self._check_ip_prefix_valid(destination_ip_prefix, ethertype)
        logical_source_port = fc['logical_source_port']
        logical_destination_port = fc['logical_destination_port']
        with db_api.CONTEXT_WRITER.using(context):
            if logical_source_port is not None:
                self._get_port(context, logical_source_port)
            if logical_destination_port is not None:
                self._get_port(context, logical_destination_port)
            query = model_query.query_with_hooks(context, FlowClassifier)
            for flow_classifier_db in query.all():
                if self.flowclassifier_conflict(
                    fc,
                    flow_classifier_db
                ):
                    raise fc_ext.FlowClassifierInConflict(
                        id=flow_classifier_db['id']
                    )
            flow_classifier_db = FlowClassifier(
                id=uuidutils.generate_uuid(),
                project_id=project_id,
                name=fc['name'],
                description=fc['description'],
                ethertype=ethertype,
                protocol=protocol,
                source_port_range_min=source_port_range_min,
                source_port_range_max=source_port_range_max,
                destination_port_range_min=destination_port_range_min,
                destination_port_range_max=destination_port_range_max,
                source_ip_prefix=source_ip_prefix,
                destination_ip_prefix=destination_ip_prefix,
                logical_source_port=logical_source_port,
                logical_destination_port=logical_destination_port,
                l7_parameters=l7_parameters
            )
            context.session.add(flow_classifier_db)
            return self._make_flow_classifier_dict(flow_classifier_db)

    def _make_flow_classifier_dict(self, flow_classifier, fields=None):
        res = {
            'id': flow_classifier['id'],
            'name': flow_classifier['name'],
            'description': flow_classifier['description'],
            'project_id': flow_classifier['project_id'],
            'ethertype': flow_classifier['ethertype'],
            'protocol': flow_classifier['protocol'],
            'source_port_range_min': flow_classifier['source_port_range_min'],
            'source_port_range_max': flow_classifier['source_port_range_max'],
            'destination_port_range_min': (
                flow_classifier['destination_port_range_min']),
            'destination_port_range_max': (
                flow_classifier['destination_port_range_max']),
            'source_ip_prefix': flow_classifier['source_ip_prefix'],
            'destination_ip_prefix': flow_classifier[
                'destination_ip_prefix'],
            'logical_source_port': flow_classifier['logical_source_port'],
            'logical_destination_port': flow_classifier[
                'logical_destination_port'],
            'l7_parameters': {
                param['keyword']: param['value']
                for k, param in flow_classifier.l7_parameters.items()
            }
        }
        return db_utils.resource_fields(res, fields)

    @log_helpers.log_method_call
    @db_api.CONTEXT_READER
    def get_flow_classifiers(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        marker_obj = db_utils.get_marker_obj(self, context, 'flow_classifier',
                                             limit, marker)
        return model_query.get_collection(
            context,
            FlowClassifier,
            self._make_flow_classifier_dict,
            filters=filters, fields=fields,
            sorts=sorts,
            limit=limit, marker_obj=marker_obj,
            page_reverse=page_reverse)

    @log_helpers.log_method_call
    @db_api.CONTEXT_READER
    def get_flow_classifier(self, context, id, fields=None):
        flow_classifier = self._get_flow_classifier(context, id)
        return self._make_flow_classifier_dict(flow_classifier, fields)

    def _get_flow_classifier(self, context, id):
        try:
            return model_query.get_by_id(context, FlowClassifier, id)
        except exc.NoResultFound as no_res_found:
            raise fc_ext.FlowClassifierNotFound(id=id) from no_res_found

    def _get_port(self, context, id):
        try:
            return model_query.get_by_id(context, models_v2.Port, id)
        except exc.NoResultFound as no_res_found:
            raise fc_ext.FlowClassifierPortNotFound(id=id) from no_res_found

    @log_helpers.log_method_call
    def update_flow_classifier(self, context, id, flow_classifier):
        new_fc = flow_classifier['flow_classifier']
        with db_api.CONTEXT_WRITER.using(context):
            old_fc = self._get_flow_classifier(context, id)
            old_fc.update(new_fc)
            return self._make_flow_classifier_dict(old_fc)

    @log_helpers.log_method_call
    def delete_flow_classifier(self, context, id):
        try:
            with db_api.CONTEXT_WRITER.using(context):
                fc = self._get_flow_classifier(context, id)
                context.session.delete(fc)
        except AssertionError as exc:
            raise fc_ext.FlowClassifierInUse(id=id) from exc
        except fc_ext.FlowClassifierNotFound:
            LOG.info("Deleting a non-existing flow classifier.")
