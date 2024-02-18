# Copyright 2017 Futurewei. All rights reserved.
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
#

from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
from neutron_lib.db import model_base
from neutron_lib.db import model_query
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy import sql

from oslo_utils import uuidutils

from networking_sfc._i18n import _


class PortPairDetailNotFound(n_exc.NotFound):
    message = _("Portchain port brief %(port_id)s could not be found")


class NodeNotFound(n_exc.NotFound):
    message = _("Portchain node %(node_id)s could not be found")


# name changed to ChainPathId
class UuidIntidAssoc(model_base.BASEV2, model_base.HasId):
    __tablename__ = 'sfc_uuid_intid_associations'
    uuid = sa.Column(sa.String(36), primary_key=True)
    intid = sa.Column(sa.Integer, unique=True, nullable=False)
    type_ = sa.Column(sa.String(32), nullable=False)

    def __init__(self, uuid, intid, type_):
        self.uuid = uuid
        self.intid = intid
        self.type_ = type_


def singleton(class_):
    instances = {}

    def getinstance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]

    return getinstance


class PathPortAssoc(model_base.BASEV2):
    """path port association table.

    It represents the association table which associate path_nodes with
    portpair_details.
    """
    __tablename__ = 'sfc_path_port_associations'
    pathnode_id = sa.Column(sa.String(36),
                            sa.ForeignKey(
                                'sfc_path_nodes.id', ondelete='CASCADE'),
                            primary_key=True)
    portpair_id = sa.Column(sa.String(36),
                            sa.ForeignKey('sfc_portpair_details.id',
                                          ondelete='CASCADE'),
                            primary_key=True)
    weight = sa.Column(sa.Integer, nullable=False, default=1)


class PortPairDetail(model_base.BASEV2, model_base.HasId,
                     model_base.HasProject):
    __tablename__ = 'sfc_portpair_details'
    ingress = sa.Column(sa.String(36), nullable=True)
    egress = sa.Column(sa.String(36), nullable=True)
    host_id = sa.Column(sa.String(255), nullable=False)
    in_mac_address = sa.Column(sa.String(32))
    mac_address = sa.Column(sa.String(32), nullable=False)
    network_type = sa.Column(sa.String(8))
    segment_id = sa.Column(sa.Integer)
    local_endpoint = sa.Column(sa.String(64), nullable=False)
    path_nodes = orm.relationship(PathPortAssoc,
                                  backref='port_pair_detail',
                                  lazy="joined",
                                  cascade='all,delete')
    correlation = sa.Column(sa.String(255), nullable=True)


class PathNode(model_base.BASEV2, model_base.HasId, model_base.HasProject):
    __tablename__ = 'sfc_path_nodes'
    nsp = sa.Column(sa.Integer, nullable=False)
    nsi = sa.Column(sa.Integer, nullable=False)
    node_type = sa.Column(sa.String(32))
    portchain_id = sa.Column(
        sa.String(255),
        sa.ForeignKey('sfc_port_chains.id', ondelete='CASCADE'))
    status = sa.Column(sa.String(32))
    portpair_details = orm.relationship(PathPortAssoc,
                                        backref='path_nodes',
                                        lazy="joined",
                                        cascade='all,delete')
    next_group_id = sa.Column(sa.Integer)
    next_hop = sa.Column(sa.String(512))
    fwd_path = sa.Column(sa.Boolean(),
                         nullable=False)
    ppg_n_tuple_mapping = sa.Column(sa.String(1024), nullable=True)
    tap_enabled = sa.Column(sa.Boolean(),
                            nullable=False,
                            server_default=sa.sql.false())
    previous_node_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('sfc_path_nodes.id', ondelete='SET NULL'))


class OVSSfcDriverDB():
    def initialize(self):
        self.admin_context = n_context.get_admin_context()

    def _make_pathnode_dict(self, node, fields=None):
        res = {'id': node['id'],
               'project_id': node['project_id'],
               'node_type': node['node_type'],
               'nsp': node['nsp'],
               'nsi': node['nsi'],
               'next_group_id': node['next_group_id'],
               'next_hop': node['next_hop'],
               'portchain_id': node['portchain_id'],
               'status': node['status'],
               'portpair_details': [pair_detail['portpair_id']
                                    for pair_detail in node['portpair_details']
                                    ],
               'fwd_path': node['fwd_path'],
               'ppg_n_tuple_mapping': node['ppg_n_tuple_mapping'],
               'tap_enabled': node['tap_enabled'],
               'previous_node_id': node['previous_node_id']
               }

        return db_utils.resource_fields(res, fields)

    def _make_port_detail_dict(self, port, fields=None):
        res = {'id': port['id'],
               'project_id': port['project_id'],
               'host_id': port['host_id'],
               'ingress': port.get('ingress', None),
               'egress': port.get('egress', None),
               'segment_id': port['segment_id'],
               'local_endpoint': port['local_endpoint'],
               'mac_address': port['mac_address'],
               'in_mac_address': port['in_mac_address'],
               'network_type': port['network_type'],
               'path_nodes': [{'pathnode_id': node['pathnode_id'],
                               'weight': node['weight']}
                              for node in port['path_nodes']],
               'correlation': port['correlation']
               }

        return db_utils.resource_fields(res, fields)

    def _make_pathport_assoc_dict(self, assoc, fields=None):
        res = {'pathnode_id': assoc['pathnode_id'],
               'portpair_id': assoc['portpair_id'],
               'weight': assoc['weight'],
               }

        return db_utils.resource_fields(res, fields)

    def _get_path_node(self, id):
        try:
            node = model_query.get_by_id(self.admin_context, PathNode, id)
        except exc.NoResultFound as no_res_found:
            raise NodeNotFound(node_id=id) from no_res_found
        return node

    def _get_port_pair_detail(self, id):
        try:
            port = model_query.get_by_id(
                self.admin_context, PortPairDetail, id)
        except exc.NoResultFound as no_res_found:
            raise PortPairDetailNotFound(port_id=id) from no_res_found
        return port

    def create_port_pair_detail(self, port):
        with db_api.CONTEXT_WRITER.using(self.admin_context):
            args = db_utils.filter_non_model_columns(port, PortPairDetail)
            args['id'] = uuidutils.generate_uuid()
            port_obj = PortPairDetail(**args)
            self.admin_context.session.add(port_obj)
            return self._make_port_detail_dict(port_obj)

    def create_path_node(self, node):
        with db_api.CONTEXT_WRITER.using(self.admin_context):
            args = db_utils.filter_non_model_columns(node, PathNode)
            args['id'] = uuidutils.generate_uuid()
            node_obj = PathNode(**args)
            self.admin_context.session.add(node_obj)
            return self._make_pathnode_dict(node_obj)

    def create_pathport_assoc(self, assoc):
        with db_api.CONTEXT_WRITER.using(self.admin_context):
            args = db_utils.filter_non_model_columns(assoc, PathPortAssoc)
            assoc_obj = PathPortAssoc(**args)
            self.admin_context.session.add(assoc_obj)
            return self._make_pathport_assoc_dict(assoc_obj)

    def delete_pathport_assoc(self, pathnode_id, portdetail_id):
        with db_api.CONTEXT_WRITER.using(self.admin_context):
            self.admin_context.session.query(PathPortAssoc).filter_by(
                pathnode_id=pathnode_id,
                portpair_id=portdetail_id).delete()

    def update_port_detail(self, id, port):
        with db_api.CONTEXT_WRITER.using(self.admin_context):
            port_obj = self._get_port_detail(id)
            for key, value in port.items():
                if key == 'path_nodes':
                    pns = []
                    for pn in value:
                        pn_id = pn['pathnode_id']
                        self._get_path_node(pn_id)
                        query = model_query.query_with_hooks(
                            self.admin_context, PathPortAssoc)
                        pn_association = query.filter_by(
                            pathnode_id=pn_id,
                            portpair_id=id
                        ).first()
                        if not pn_association:
                            pn_association = PathPortAssoc(
                                pathnode_id=pn_id,
                                portpair_id=id,
                                weight=pn.get('weight', 1)
                            )
                        pns.append(pn_association)
                    port_obj[key] = pns
                else:
                    port_obj[key] = value
            port_obj.update(port)
            return self._make_port_detail_dict(port_obj)

    def update_path_node(self, id, node):
        with db_api.CONTEXT_WRITER.using(self.admin_context):
            node_obj = self._get_path_node(id)
            for key, value in node.items():
                if key == 'portpair_details':
                    pds = []
                    for pd_id in value:
                        query = model_query.query_with_hooks(
                            self.admin_context, PathPortAssoc)
                        pd_association = query.filter_by(
                            pathnode_id=id,
                            portpair_id=pd_id
                        ).first()
                        if not pd_association:
                            pd_association = PathPortAssoc(
                                pathnode_id=id,
                                portpair_id=pd_id
                            )
                        pds.append(pd_association)
                    node_obj[key] = pds
                else:
                    node_obj[key] = value

            return self._make_pathnode_dict(node_obj)

    def delete_port_pair_detail(self, id):
        with db_api.CONTEXT_WRITER.using(self.admin_context):
            port_obj = self._get_port_pair_detail(id)
            self.admin_context.session.delete(port_obj)

    def delete_path_node(self, id):
        with db_api.CONTEXT_WRITER.using(self.admin_context):
            node_obj = self._get_path_node(id)
            self.admin_context.session.delete(node_obj)

    def get_port_detail(self, id):
        with db_api.CONTEXT_READER.using(self.admin_context):
            port_obj = self._get_port_pair_detail(id)
            return self._make_port_detail_dict(port_obj)

    def get_port_detail_without_exception(self, id):
        with db_api.CONTEXT_READER.using(self.admin_context):
            try:
                port = model_query.get_by_id(
                    self.admin_context, PortPairDetail, id)
            except exc.NoResultFound:
                return None
            return self._make_port_detail_dict(port)

    def get_path_node(self, id):
        with db_api.CONTEXT_READER.using(self.admin_context):
            node_obj = self._get_path_node(id)
        return self._make_pathnode_dict(node_obj)

    def get_path_nodes_by_filter(self, filters=None):
        with db_api.CONTEXT_READER.using(self.admin_context):
            qry = self._get_path_nodes_by_filter(filters)
            all_items = qry.all()
            if all_items:
                return [self._make_pathnode_dict(item) for item in all_items]
        return None

    def get_path_node_by_filter(self, filters=None):
        with db_api.CONTEXT_READER.using(self.admin_context):
            qry = self._get_path_nodes_by_filter(filters)
            first = qry.first()
            if first:
                return self._make_pathnode_dict(first)
        return None

    def _get_path_nodes_by_filter(self, filters=None):
        qry = self.admin_context.session.query(PathNode)
        if filters:
            for key, value in filters.items():
                column = getattr(PathNode, key, None)
                if column:
                    if not value:
                        qry = qry.filter(sql.false())
                    else:
                        qry = qry.filter(column == value)
        return qry

    def get_port_details_by_filter(self, filters=None):
        with db_api.CONTEXT_READER.using(self.admin_context):
            qry = self._get_port_details_by_filter(filters)
            all_items = qry.all()
            if all_items:
                return [self._make_port_detail_dict(item)
                        for item in all_items]
        return None

    def get_port_detail_by_filter(self, filters=None):
        with db_api.CONTEXT_READER.using(self.admin_context):
            qry = self._get_port_details_by_filter(filters)
            first = qry.first()
            if first:
                return self._make_port_detail_dict(first)
        return None

    def _get_port_details_by_filter(self, filters=None):
        qry = self.admin_context.session.query(PortPairDetail)
        if filters:
            for key, value in filters.items():
                column = getattr(PortPairDetail, key, None)
                if column:
                    if not value:
                        qry = qry.filter(sql.false())
                    else:
                        qry = qry.filter(column == value)
        return qry
