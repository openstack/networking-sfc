# Copyright 2015 Futurewei. All rights reserved.
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

from abc import ABCMeta
from abc import abstractmethod

from neutron_lib.api import attributes as attr
from neutron_lib.api import converters
from neutron_lib.api import extensions
from neutron_lib import constants as const
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions as neutron_exc
from neutron_lib.services import base as service_base
from oslo_config import cfg

from neutron.api import extensions as neutron_ext
from neutron.api.v2 import resource_helper
from neutron.common import config as common_config
from neutron.conf import service as service_config

from networking_sfc._i18n import _
from networking_sfc import extensions as sfc_extensions

common_config.register_common_config_options()
service_config.register_service_opts(service_config.SERVICE_OPTS, cfg.CONF)
cfg.CONF.import_opt('api_extensions_path', 'neutron.common.config')
neutron_ext.append_api_extensions_path(sfc_extensions.__path__)
FLOW_CLASSIFIER_EXT = "flow_classifier"
FLOW_CLASSIFIER_PREFIX = "/sfc"

fc_supported_protocols = [const.PROTO_NAME_TCP,
                          const.PROTO_NAME_UDP, const.PROTO_NAME_ICMP]
fc_supported_ethertypes = ['IPv4', 'IPv6']
SUPPORTED_L7_PARAMETERS = {}
_l7_param_attrs = attr.AttributeInfo(SUPPORTED_L7_PARAMETERS)


# Flow Classifier Exceptions
class FlowClassifierNotFound(neutron_exc.NotFound):
    message = _("Flow Classifier %(id)s not found.")


class FlowClassifierPortNotFound(neutron_exc.NotFound):
    message = _("Flow Classifier Neutron Port %(id)s not found.")


class FlowClassifierInvalidPortRange(neutron_exc.InvalidInput):
    message = _("Invalid IP protocol port range. min_port_range="
                "%(port_range_min)s must be lesser or equal to "
                "max_port_range=%(port_range_max)s.")


class FlowClassifierInvalidPortValue(neutron_exc.InvalidInput):
    message = _("Flow Classifier has invalid port value %(port)s.")


class FlowClassiferDuplicateInformation(neutron_exc.InvalidInput):
    message = _("Flow Classifier has duplicate information: "
                "Neutron Port id %(port_id)s and ip prefix %(ip_prefix)s.")


class FlowClassifierInUse(neutron_exc.InUse):
    message = _("Flow Classifier %(id)s in use.")


class FlowClassifierInConflict(neutron_exc.InvalidInput):
    message = _("Flow Classifier conflicts with "
                "another Flow Classifier %(id)s.")


class FlowClassifierInvalidProtocol(neutron_exc.InvalidInput):
    message = _("Flow Classifier does not support protocol %(protocol)s. "
                "Supported protocol values are %(values)s.")


class FlowClassifierInvalidEthertype(neutron_exc.InvalidInput):
    message = _("Flow Classifier does not support ethertype %(ethertype)s. "
                "Supported ethertype values are %(values)s.")


class FlowClassifierProtocolRequiredWithPorts(neutron_exc.InvalidInput):
    message = _("IP protocol must be TCP or UDP, if port range is given.")


class FlowClassifierIpPrefixFormatConflictWithEthertype(
    neutron_exc.InvalidInput
):
    message = _("IP prefix %(ip_prefix)s format conflicts with "
                "ethertype %(ethertype)s.")


class FlowClassifierInvalidL7Parameter(neutron_exc.InvalidInput):
    message = _(
        "Invalid Flow Classifier parameters: %%(error_message)s. "
        "Supported flow classifier parameters are %(supported_parameters)s."
    ) % {'supported_parameters': SUPPORTED_L7_PARAMETERS}


def normalize_protocol(value):
    if value is None:
        return None
    if isinstance(value, str):
        if value.lower() in fc_supported_protocols:
            return value.lower()
    raise FlowClassifierInvalidProtocol(
        protocol=value, values=fc_supported_protocols)


def normalize_ethertype(value):
    if value is None:
        return 'IPv4'
    if isinstance(value, str):
        for ether_type in fc_supported_ethertypes:
            if value.lower() == ether_type.lower():
                return ether_type
    raise FlowClassifierInvalidEthertype(
        ethertype=value, values=fc_supported_ethertypes)


def normalize_string(value):
    if value is None:
        return ''
    return value


def normalize_port_value(port):
    if port is None:
        return None
    try:
        val = int(port)
    except (ValueError, TypeError) as exc:
        raise FlowClassifierInvalidPortValue(port=port) from exc

    if 0 <= val <= 65535:
        return val
    else:
        raise FlowClassifierInvalidPortValue(port=port)


def normalize_l7parameters(parameters):
    parameters = converters.convert_none_to_empty_dict(parameters)
    for key in parameters:
        if key not in SUPPORTED_L7_PARAMETERS:
            raise FlowClassifierInvalidL7Parameter(
                error_message='Unknown key %s.' % key)
    try:
        _l7_param_attrs.fill_post_defaults(parameters)
        attr.populate_project_info(SUPPORTED_L7_PARAMETERS)
        _l7_param_attrs.convert_values(parameters)
    except ValueError as error:
        raise FlowClassifierInvalidL7Parameter(
            error_message=str(error)) from error
    return parameters


# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'flow_classifiers': {
        'id': {
            'allow_post': False, 'allow_put': False,
            'is_visible': True,
            'validate': {'type:uuid': None},
            'primary_key': True},
        'name': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': None,
            'validate': {'type:string': db_const.NAME_FIELD_SIZE},
            'convert_to': normalize_string},
        'description': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': None,
            'validate': {'type:string': db_const.DESCRIPTION_FIELD_SIZE},
            'convert_to': normalize_string},
        'tenant_id': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True,
            'validate': {'type:string': db_const.PROJECT_ID_FIELD_SIZE},
            'required_by_policy': True},
        'ethertype': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'convert_to': normalize_ethertype},
        'protocol': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'convert_to': normalize_protocol},
        'source_port_range_min': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'convert_to': normalize_port_value},
        'source_port_range_max': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'convert_to': normalize_port_value},
        'destination_port_range_min': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'convert_to': normalize_port_value},
        'destination_port_range_max': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'convert_to': normalize_port_value},
        'source_ip_prefix': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'validate': {'type:subnet_or_none': None}},
        'destination_ip_prefix': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'validate': {'type:subnet_or_none': None}},
        'logical_source_port': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'validate': {'type:uuid_or_none': None}},
        'logical_destination_port': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'validate': {'type:uuid_or_none': None}},
        'l7_parameters': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'validate': {'type:dict': None},
            'convert_to': normalize_l7parameters},
    },
}

flow_classifier_quota_opts = [
    cfg.IntOpt('quota_flow_classifier',
               default=100,
               help=_('Maximum number of Flow Classifiers per tenant. '
                      'A negative value means unlimited.')),
]
cfg.CONF.register_opts(flow_classifier_quota_opts, 'QUOTAS')


class Flowclassifier(extensions.ExtensionDescriptor):
    """Flow Classifier extension."""

    @classmethod
    def get_name(cls):
        return "Flow Classifier"

    @classmethod
    def get_alias(cls):
        return FLOW_CLASSIFIER_EXT

    @classmethod
    def get_description(cls):
        return "Flow Classifier Extension."

    @classmethod
    def get_plugin_interface(cls):
        return FlowClassifierPluginBase

    @classmethod
    def get_updated(cls):
        return "2015-10-05T10:00:00-00:00"

    @classmethod
    def update_attributes_map(cls, extended_attributes,
                              extension_attrs_map=None):
        super().update_attributes_map(
            extended_attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        plural_mappings['flow_classifiers'] = 'flow_classifier'
        return resource_helper.build_resource_info(
            plural_mappings,
            RESOURCE_ATTRIBUTE_MAP,
            FLOW_CLASSIFIER_EXT,
            register_quota=True)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        return {}


class FlowClassifierPluginBase(service_base.ServicePluginBase,
                               metaclass=ABCMeta):

    def get_plugin_type(self):
        return FLOW_CLASSIFIER_EXT

    def get_plugin_description(self):
        return 'Flow Classifier plugin'

    @abstractmethod
    def create_flow_classifier(self, context, flow_classifier):
        pass

    @abstractmethod
    def update_flow_classifier(self, context, id, flow_classifier):
        pass

    @abstractmethod
    def delete_flow_classifier(self, context, id):
        pass

    @abstractmethod
    def get_flow_classifiers(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        pass

    @abstractmethod
    def get_flow_classifier(self, context, id, fields=None):
        pass
