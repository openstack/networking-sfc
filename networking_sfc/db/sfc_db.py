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

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

import sqlalchemy as sa
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy import orm
from sqlalchemy.orm import backref
from sqlalchemy.orm.collections import attribute_mapped_collection
from sqlalchemy.orm import exc

from neutron.db import api as db_api
from neutron.db import common_db_mixin
from neutron.db import models_v2
from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base

from networking_sfc.db import flowclassifier_db as fc_db
from networking_sfc.extensions import flowclassifier as ext_fc
from networking_sfc.extensions import sfc as ext_sfc


LOG = logging.getLogger(__name__)

UUID_LEN = 36
PARAM_LEN = 255
VAR_MAX_LEN = 1024


class ChainParameter(model_base.BASEV2):
    """Represents a single chain parameter."""
    __tablename__ = 'sfc_port_chain_parameters'
    keyword = sa.Column(sa.String(PARAM_LEN), primary_key=True)
    value = sa.Column(sa.String(PARAM_LEN))
    chain_id = sa.Column(
        sa.String(UUID_LEN),
        sa.ForeignKey('sfc_port_chains.id', ondelete='CASCADE'),
        primary_key=True)


class ServiceFunctionParam(model_base.BASEV2):
    """Represents a service function parameter."""
    __tablename__ = 'sfc_service_function_params'
    keyword = sa.Column(sa.String(PARAM_LEN), primary_key=True)
    value = sa.Column(sa.String(PARAM_LEN))
    pair_id = sa.Column(
        sa.String(UUID_LEN),
        sa.ForeignKey('sfc_port_pairs.id', ondelete='CASCADE'),
        primary_key=True)


class PortPairGroupParam(model_base.BASEV2):
    """Represents a port pair group parameter."""
    __tablename__ = 'sfc_port_pair_group_params'
    keyword = sa.Column(sa.String(PARAM_LEN), primary_key=True)
    value = sa.Column(sa.String(VAR_MAX_LEN))
    pair_group_id = sa.Column(
        sa.String(UUID_LEN),
        sa.ForeignKey('sfc_port_pair_groups.id', ondelete='CASCADE'),
        primary_key=True)


class ChainClassifierAssoc(model_base.BASEV2):
    """Relation table between sfc_port_chains and flow_classifiers."""
    __tablename__ = 'sfc_chain_classifier_associations'
    flowclassifier_id = sa.Column(
        sa.String(UUID_LEN),
        sa.ForeignKey('sfc_flow_classifiers.id', ondelete='RESTRICT'),
        primary_key=True, nullable=False, unique=True)
    portchain_id = sa.Column(
        sa.String(UUID_LEN),
        sa.ForeignKey('sfc_port_chains.id', ondelete='CASCADE'),
        primary_key=True)
    flow_classifier = orm.relationship(
        fc_db.FlowClassifier,
        backref=backref('chain_classifier_association', uselist=False),
        uselist=False
    )


class PortPair(model_base.BASEV2, model_base.HasId, model_base.HasProject):
    """Represents the ingress and egress ports for a single service function.

    """
    __tablename__ = 'sfc_port_pairs'
    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    description = sa.Column(sa.String(db_const.DESCRIPTION_FIELD_SIZE))
    ingress = sa.Column(
        sa.String(UUID_LEN),
        sa.ForeignKey('ports.id', ondelete='RESTRICT'),
        nullable=False)
    egress = sa.Column(
        sa.String(UUID_LEN),
        sa.ForeignKey('ports.id', ondelete='RESTRICT'),
        nullable=False)

    portpairgroup_id = sa.Column(
        sa.String(UUID_LEN),
        sa.ForeignKey('sfc_port_pair_groups.id', ondelete='RESTRICT'))
    service_function_parameters = orm.relationship(
        ServiceFunctionParam,
        collection_class=attribute_mapped_collection('keyword'),
        cascade='all, delete-orphan')

    __table_args__ = (
        sa.UniqueConstraint(
            ingress, egress,
            name='uniq_sfc_port_pairs0ingress0egress'
        ),
        model_base.BASEV2.__table_args__
    )


class ChainGroupAssoc(model_base.BASEV2):
    """Relation table between sfc_port_chains and sfc_port_pair_groups."""
    __tablename__ = 'sfc_chain_group_associations'
    portpairgroup_id = sa.Column(
        sa.String(UUID_LEN),
        sa.ForeignKey('sfc_port_pair_groups.id', ondelete='RESTRICT'),
        primary_key=True, nullable=False)
    portchain_id = sa.Column(
        sa.String(UUID_LEN),
        sa.ForeignKey('sfc_port_chains.id', ondelete='CASCADE'),
        primary_key=True)
    position = sa.Column(sa.Integer)


class PortPairGroup(model_base.BASEV2, model_base.HasId,
                    model_base.HasProject):
    """Represents a port pair group model."""
    __tablename__ = 'sfc_port_pair_groups'
    group_id = sa.Column(sa.Integer(), unique=True, nullable=False)
    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    description = sa.Column(sa.String(db_const.DESCRIPTION_FIELD_SIZE))
    port_pairs = orm.relationship(
        PortPair,
        backref='port_pair_group'
    )
    port_pair_group_parameters = orm.relationship(
        PortPairGroupParam,
        collection_class=attribute_mapped_collection('keyword'),
        cascade='all, delete-orphan')
    chain_group_associations = orm.relationship(
        ChainGroupAssoc,
        backref='port_pair_groups')


class PortChain(model_base.BASEV2, model_base.HasId, model_base.HasProject):
    """Represents a Neutron service function Port Chain."""
    __tablename__ = 'sfc_port_chains'
    chain_id = sa.Column(sa.Integer(), unique=True, nullable=False)
    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    description = sa.Column(sa.String(db_const.DESCRIPTION_FIELD_SIZE))
    chain_group_associations = orm.relationship(
        ChainGroupAssoc,
        backref='port_chain',
        order_by="ChainGroupAssoc.position",
        collection_class=ordering_list('position'),
        cascade='all, delete-orphan')
    chain_classifier_associations = orm.relationship(
        ChainClassifierAssoc,
        backref='port_chain',
        cascade='all, delete-orphan')
    chain_parameters = orm.relationship(
        ChainParameter,
        collection_class=attribute_mapped_collection('keyword'),
        cascade='all, delete-orphan')


class SfcDbPlugin(
    ext_sfc.SfcPluginBase,
    common_db_mixin.CommonDbMixin
):
    """Mixin class to add port chain to db_plugin_base_v2."""

    def _make_port_chain_dict(self, port_chain, fields=None):
        res = {
            'id': port_chain['id'],
            'name': port_chain['name'],
            'project_id': port_chain['project_id'],
            'description': port_chain['description'],
            'port_pair_groups': [
                assoc['portpairgroup_id']
                for assoc in port_chain['chain_group_associations']
            ],
            'flow_classifiers': [
                assoc['flowclassifier_id']
                for assoc in port_chain['chain_classifier_associations']
            ],
            'chain_parameters': {
                param['keyword']: jsonutils.loads(param['value'])
                for k, param in port_chain['chain_parameters'].items()
            },
            'chain_id': port_chain['chain_id'],
        }
        return self._fields(res, fields)

    def _validate_port_pair_groups(self, context, pg_ids, pc_id=None):
        with db_api.context_manager.reader.using(context):
            for pg_id in pg_ids:
                self._get_port_pair_group(context, pg_id)
            query = self._model_query(context, PortChain)
            for port_chain_db in query.all():
                if port_chain_db['id'] == pc_id:
                    continue
                pc_pg_ids = [
                    assoc['portpairgroup_id']
                    for assoc in port_chain_db.chain_group_associations
                ]
                if pc_pg_ids and pg_ids and pc_pg_ids == pg_ids:
                    raise ext_sfc.InvalidPortPairGroups(
                        port_pair_groups=pg_ids, port_chain=port_chain_db.id)

    def _validate_flow_classifiers(self, context, fc_ids, pc_id=None):
        with db_api.context_manager.reader.using(context):
            fcs = [
                self._get_flow_classifier(context, fc_id)
                for fc_id in fc_ids
            ]
            for fc in fcs:
                fc_assoc = fc.chain_classifier_association
                if fc_assoc and fc_assoc['portchain_id'] != pc_id:
                    raise ext_fc.FlowClassifierInUse(id=fc.id)

            query = self._model_query(context, PortChain)
            for port_chain_db in query.all():
                if port_chain_db['id'] == pc_id:
                    continue
                pc_fc_ids = [
                    assoc['flowclassifier_id']
                    for assoc in port_chain_db.chain_classifier_associations
                ]
                pc_fcs = [
                    self._get_flow_classifier(context, pc_fc_id)
                    for pc_fc_id in pc_fc_ids
                ]
                for pc_fc in pc_fcs:
                    for fc in fcs:
                        fc_cls = fc_db.FlowClassifierDbPlugin
                        if fc_cls.flowclassifier_basic_conflict(
                            pc_fc, fc
                        ):
                            raise ext_sfc.PortChainFlowClassifierInConflict(
                                fc_id=fc['id'], pc_id=port_chain_db['id'],
                                pc_fc_id=pc_fc['id']
                            )

    def _setup_chain_group_associations(
        self, context, port_chain, pg_ids
    ):
        with db_api.context_manager.reader.using(context):
            chain_group_associations = []
            for pg_id in pg_ids:
                query = self._model_query(context, ChainGroupAssoc)
                chain_group_association = query.filter_by(
                    portchain_id=port_chain.id, portpairgroup_id=pg_id
                ).first()
                if not chain_group_association:
                    chain_group_association = ChainGroupAssoc(
                        portpairgroup_id=pg_id
                    )
                chain_group_associations.append(chain_group_association)
            port_chain.chain_group_associations = chain_group_associations

    def _setup_chain_classifier_associations(
        self, context, port_chain, fc_ids
    ):
        with db_api.context_manager.reader.using(context):
            chain_classifier_associations = []
            for fc_id in fc_ids:
                query = self._model_query(context, ChainClassifierAssoc)
                chain_classifier_association = query.filter_by(
                    portchain_id=port_chain.id, flowclassifier_id=fc_id
                ).first()
                if not chain_classifier_association:
                    chain_classifier_association = ChainClassifierAssoc(
                        flowclassifier_id=fc_id
                    )
                chain_classifier_associations.append(
                    chain_classifier_association)
            port_chain.chain_classifier_associations = (
                chain_classifier_associations)

    @log_helpers.log_method_call
    def create_port_chain(self, context, port_chain):
        """Create a port chain."""
        pc = port_chain['port_chain']
        project_id = pc['project_id']
        chain_id = pc['chain_id']
        with db_api.context_manager.writer.using(context):
            chain_parameters = {
                key: ChainParameter(keyword=key, value=jsonutils.dumps(val))
                for key, val in pc['chain_parameters'].items()}

            pg_ids = pc['port_pair_groups']
            fc_ids = pc['flow_classifiers']
            self._validate_port_pair_groups(context, pg_ids)
            self._validate_flow_classifiers(context, fc_ids)
            assigned_chain_ids = {}
            query = context.session.query(PortChain)
            for port_chain_db in query.all():
                assigned_chain_ids[port_chain_db['chain_id']] = (
                    port_chain_db['id']
                )
            if not chain_id:
                available_chain_id = 1
                while available_chain_id < ext_sfc.MAX_CHAIN_ID:
                    if available_chain_id not in assigned_chain_ids:
                        chain_id = available_chain_id
                        break
                    available_chain_id += 1
                if not chain_id:
                    raise ext_sfc.PortChainUnavailableChainId()
            else:
                if chain_id in assigned_chain_ids:
                    raise ext_sfc.PortChainChainIdInConflict(
                        chain_id=chain_id, pc_id=assigned_chain_ids[chain_id])
            port_chain_db = PortChain(id=uuidutils.generate_uuid(),
                                      project_id=project_id,
                                      description=pc['description'],
                                      name=pc['name'],
                                      chain_parameters=chain_parameters,
                                      chain_id=chain_id)
            self._setup_chain_group_associations(
                context, port_chain_db, pg_ids)
            self._setup_chain_classifier_associations(
                context, port_chain_db, fc_ids)
            context.session.add(port_chain_db)

            return self._make_port_chain_dict(port_chain_db)

    @log_helpers.log_method_call
    def get_port_chains(self, context, filters=None, fields=None,
                        sorts=None, limit=None,
                        marker=None, page_reverse=False, default_sg=False):

        marker_obj = self._get_marker_obj(context, 'port_chain', limit, marker)
        return self._get_collection(context,
                                    PortChain,
                                    self._make_port_chain_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit, marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_port_chains_count(self, context, filters=None):
        return self._get_collection_count(context, PortChain,
                                          filters=filters)

    @log_helpers.log_method_call
    def get_port_chain(self, context, id, fields=None):
        portchain = self._get_port_chain(context, id)
        return self._make_port_chain_dict(portchain, fields)

    @log_helpers.log_method_call
    def _get_port_chain(self, context, id):
        try:
            return self._get_by_id(context, PortChain, id)
        except exc.NoResultFound:
            raise ext_sfc.PortChainNotFound(id=id)

    @log_helpers.log_method_call
    def delete_port_chain(self, context, id):
        try:
            with db_api.context_manager.writer.using(context):
                pc = self._get_port_chain(context, id)
                context.session.delete(pc)
        except ext_sfc.PortChainNotFound:
            LOG.info("Deleting a non-existing port chain.")

    @log_helpers.log_method_call
    def update_port_chain(self, context, id, port_chain):
        pc = port_chain['port_chain']
        with db_api.context_manager.writer.using(context):
            pc_db = self._get_port_chain(context, id)
            for k, v in pc.items():
                if k == 'flow_classifiers':
                    self._validate_flow_classifiers(
                        context, v, pc_id=id)
                    self._setup_chain_classifier_associations(
                        context, pc_db, v)
                elif k == 'port_pair_groups':
                    self._validate_port_pair_groups(
                        context, v, pc_id=id)
                    self._setup_chain_group_associations(
                        context, pc_db, v)
                else:
                    pc_db[k] = v
            return self._make_port_chain_dict(pc_db)

    def _make_port_pair_dict(self, port_pair, fields=None):
        res = {
            'id': port_pair['id'],
            'name': port_pair['name'],
            'description': port_pair['description'],
            'project_id': port_pair['project_id'],
            'ingress': port_pair['ingress'],
            'egress': port_pair['egress'],
            'service_function_parameters': {
                param['keyword']: jsonutils.loads(param['value'])
                for k, param in
                port_pair['service_function_parameters'].items()
            }
        }

        return self._fields(res, fields)

    def _validate_port_pair_ingress_egress(self, ingress, egress):
        if 'device_id' not in ingress or not ingress['device_id']:
            raise ext_sfc.PortPairIngressNoHost(
                ingress=ingress['id']
            )
        if 'device_id' not in egress or not egress['device_id']:
            raise ext_sfc.PortPairEgressNoHost(
                egress=egress['id']
            )
        if ingress['device_id'] != egress['device_id']:
            raise ext_sfc.PortPairIngressEgressDifferentHost(
                ingress=ingress['id'],
                egress=egress['id'])

    @log_helpers.log_method_call
    def create_port_pair(self, context, port_pair):
        """Create a port pair."""
        pp = port_pair['port_pair']
        project_id = pp['project_id']
        with db_api.context_manager.writer.using(context):
            query = self._model_query(context, PortPair)
            pp_in_use = query.filter_by(
                ingress=pp['ingress'], egress=pp['egress']
            ).first()
            if pp_in_use:
                raise ext_sfc.PortPairIngressEgressInUse(
                    ingress=pp['ingress'],
                    egress=pp['egress'],
                    id=pp_in_use['id']
                )

            service_function_parameters = {
                key: ServiceFunctionParam(
                    keyword=key, value=jsonutils.dumps(val))
                for key, val in
                pp['service_function_parameters'].items()
            }
            ingress = self._get_port(context, pp['ingress'])
            egress = self._get_port(context, pp['egress'])
            self._validate_port_pair_ingress_egress(ingress, egress)
            port_pair_db = PortPair(
                id=uuidutils.generate_uuid(),
                name=pp['name'],
                description=pp['description'],
                project_id=project_id,
                ingress=pp['ingress'],
                egress=pp['egress'],
                service_function_parameters=service_function_parameters
            )
            context.session.add(port_pair_db)
            return self._make_port_pair_dict(port_pair_db)

    @log_helpers.log_method_call
    def get_port_pairs(self, context, filters=None, fields=None,
                       sorts=None, limit=None, marker=None,
                       page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'port_pair',
                                          limit, marker)
        return self._get_collection(context,
                                    PortPair,
                                    self._make_port_pair_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit, marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_port_pairs_count(self, context, filters=None):
        return self._get_collection_count(context, PortPair,
                                          filters=filters)

    @log_helpers.log_method_call
    def get_port_pair(self, context, id, fields=None):
        port_pair = self._get_port_pair(context, id)
        return self._make_port_pair_dict(port_pair, fields)

    def _get_port_pair(self, context, id):
        try:
            return self._get_by_id(context, PortPair, id)
        except exc.NoResultFound:
            raise ext_sfc.PortPairNotFound(id=id)

    def _get_port(self, context, id):
        try:
            return self._get_by_id(context, models_v2.Port, id)
        except exc.NoResultFound:
            raise ext_sfc.PortPairPortNotFound(id=id)

    @log_helpers.log_method_call
    def update_port_pair(self, context, id, port_pair):
        new_pp = port_pair['port_pair']
        with db_api.context_manager.writer.using(context):
            old_pp = self._get_port_pair(context, id)
            old_pp.update(new_pp)
            return self._make_port_pair_dict(old_pp)

    @log_helpers.log_method_call
    def delete_port_pair(self, context, id):
        try:
            with db_api.context_manager.writer.using(context):
                pp = self._get_port_pair(context, id)
                if pp.portpairgroup_id:
                    raise ext_sfc.PortPairInUse(id=id)
                context.session.delete(pp)
        except ext_sfc.PortPairNotFound:
            LOG.info("Deleting a non-existing port pair.")

    def _make_port_pair_group_dict(self, port_pair_group, fields=None):
        res = {
            'id': port_pair_group['id'],
            'name': port_pair_group['name'],
            'description': port_pair_group['description'],
            'project_id': port_pair_group['project_id'],
            'port_pairs': [pp['id'] for pp in port_pair_group['port_pairs']],
            'port_pair_group_parameters': {
                param['keyword']: jsonutils.loads(param['value'])
                for k, param in
                port_pair_group['port_pair_group_parameters'].items()
            },
            'group_id': port_pair_group.get('group_id') or 0
        }

        return self._fields(res, fields)

    def _validate_pps_in_ppg(self, portpairs_list, id=None):
        first_check = True
        correlation = None
        for portpair in portpairs_list:
            sfparams = portpair.service_function_parameters
            pp_corr = sfparams['correlation']
            if first_check:
                first_check = False
                correlation = pp_corr.value
            if pp_corr.value != correlation:
                # don't include PPs of different correlations
                raise ext_sfc.InconsistentCorrelations()
            if (
                portpair.portpairgroup_id and
                portpair.portpairgroup_id != id
            ):
                # don't include PPs included by other PPGs
                raise ext_sfc.PortPairInUse(id=portpair.id)

    @log_helpers.log_method_call
    def create_port_pair_group(self, context, port_pair_group):
        """Create a port pair group."""
        pg = port_pair_group['port_pair_group']
        project_id = pg['project_id']

        with db_api.context_manager.writer.using(context):
            portpairs_list = [self._get_port_pair(context, pp_id)
                              for pp_id in pg['port_pairs']]
            self._validate_pps_in_ppg(portpairs_list)
            port_pair_group_parameters = {
                key: PortPairGroupParam(
                    keyword=key, value=jsonutils.dumps(val))
                for key, val in
                pg['port_pair_group_parameters'].items()
            }
            assigned_group_ids = {}
            query = context.session.query(PortPairGroup)
            for port_pair_group_db in query.all():
                assigned_group_ids[port_pair_group_db['group_id']] = (
                    port_pair_group_db['id']
                )
            group_id = 0
            available_group_id = 1
            while True:
                if available_group_id not in assigned_group_ids:
                    group_id = available_group_id
                    break
                available_group_id += 1
            port_pair_group_db = PortPairGroup(
                id=uuidutils.generate_uuid(),
                name=pg['name'],
                description=pg['description'],
                project_id=project_id,
                port_pairs=portpairs_list,
                port_pair_group_parameters=port_pair_group_parameters,
                group_id=group_id)
            context.session.add(port_pair_group_db)
            return self._make_port_pair_group_dict(port_pair_group_db)

    @log_helpers.log_method_call
    def get_port_pair_groups(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'port_pair_group',
                                          limit, marker)
        return self._get_collection(context,
                                    PortPairGroup,
                                    self._make_port_pair_group_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit, marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_port_pair_groups_count(self, context, filters=None):
        return self._get_collection_count(context, PortPairGroup,
                                          filters=filters)

    @log_helpers.log_method_call
    def get_port_pair_group(self, context, id, fields=None):
        port_pair_group = self._get_port_pair_group(context, id)
        return self._make_port_pair_group_dict(port_pair_group, fields)

    def _get_port_pair_group(self, context, id):
        try:
            return self._get_by_id(context, PortPairGroup, id)
        except exc.NoResultFound:
            raise ext_sfc.PortPairGroupNotFound(id=id)

    def _get_flow_classifier(self, context, id):
        try:
            return self._get_by_id(context, fc_db.FlowClassifier, id)
        except exc.NoResultFound:
            raise ext_fc.FlowClassifierNotFound(id=id)

    @log_helpers.log_method_call
    def update_port_pair_group(self, context, id, port_pair_group):
        new_pg = port_pair_group['port_pair_group']

        with db_api.context_manager.writer.using(context):
            portpairs_list = [self._get_port_pair(context, pp_id)
                              for pp_id in new_pg.get('port_pairs', [])]
            self._validate_pps_in_ppg(portpairs_list, id)
            old_pg = self._get_port_pair_group(context, id)
            for k, v in new_pg.items():
                if k == 'port_pairs':
                    port_pairs = [
                        self._get_port_pair(context, pp_id)
                        for pp_id in v
                    ]
                    old_pg.port_pairs = port_pairs
                else:
                    old_pg[k] = v

            return self._make_port_pair_group_dict(old_pg)

    @log_helpers.log_method_call
    def delete_port_pair_group(self, context, id):
        try:
            with db_api.context_manager.writer.using(context):
                pg = self._get_port_pair_group(context, id)
                if pg.chain_group_associations:
                    raise ext_sfc.PortPairGroupInUse(id=id)
                context.session.delete(pg)
        except ext_sfc.PortPairGroupNotFound:
            LOG.info("Deleting a non-existing port pair group.")
