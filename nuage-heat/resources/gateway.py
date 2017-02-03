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

from neutronclient.common import exceptions
from neutronclient.neutron import v2_0 as neutronV20

from heat.common import exception
from heat.common.i18n import _
from heat.engine import attributes
from heat.engine import constraints
from heat.engine import properties
from heat.engine import resource
from heat.engine.resources.openstack.neutron import neutron
from heat.engine import support
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


class GatewayConstraint(constraints.BaseCustomConstraint):

    expected_exceptions = (exceptions.NeutronClientException,)

    def validate_with_client(self, client, value):
        neutron_client = client.client('neutron')
        neutronV20.find_resourceid_by_name_or_id(
            neutron_client, 'nuage_gateway', value)


class GatewayPortConstraint(constraints.BaseCustomConstraint):

    expected_exceptions = (exceptions.NeutronClientException,)

    def validate_with_client(self, client, value):
        neutron_client = client.client('neutron')
        neutronV20.find_resourceid_by_name_or_id(
            neutron_client, 'nuage_gateway_port', value)


class GatewayPortVlanConstraint(constraints.BaseCustomConstraint):

    expected_exceptions = (exceptions.NeutronClientException,)

    def validate_with_client(self, client, value):
        neutron_client = client.client('neutron')
        neutronV20.find_resourceid_by_name_or_id(
            neutron_client, 'nuage_gateway_vlan', value)


class NuageGateway(neutron.NeutronResource):
    """
    A resource representing Nuage Gateway in Neutron.
    """

    support_status = support.SupportStatus(version='2015.1')

    PROPERTIES = (
        NAME,
    ) = (
        'name',
    )

    ATTRIBUTES = (
        NAME_ATTR,
        SYSTEMID_ATTR,
        TYPE_ATTR,
        TEMPLATE_ATTR,
        STATUS_ATTR,
        TENANT_ID_ATTR,
        SHOW,
    ) = (
        'name',
        'systemid',
        'type',
        'template',
        'status',
        'tenant_id',
        'show',
    )

    properties_schema = {
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('The name of the gateway.'),
            required=True,
            update_allowed=False
        )
    }

    attributes_schema = {
        NAME_ATTR: attributes.Schema(
            _("The name of the gateway.")
        ),
        SYSTEMID_ATTR: attributes.Schema(
            _("The system id  of the gateway.")
        ),
        TYPE_ATTR: attributes.Schema(
            _("Gateway personality")
        ),
        TEMPLATE_ATTR: attributes.Schema(
            _("Template, used to instantiate gateway.")
        ),
        STATUS_ATTR: attributes.Schema(
            _('Status of the gateway.')
        ),
        TENANT_ID_ATTR: attributes.Schema(
            _('Tenant owning gateway.')
        ),
        SHOW: attributes.Schema(
            _("All attributes.")
        ),
    }

    def _get_client(self):
        return self.neutron()

    def validate(self):
        super(NuageGateway, self).validate()

    def handle_create(self):
        props = self.prepare_properties(
            self.properties,
            self.physical_resource_name())
        gw_list = self._get_client().list_nuage_gateways(
            **props)['nuage_gateways']
        entry = next((item for item in gw_list
                     if item['name'] == props['name']), None)
        if entry is None:
            raise exception.ResourceNotAvailable(resource_name=props['name'])
        gw = self._get_client().show_nuage_gateway(
            entry['id'])['nuage_gateway']
        self.resource_id_set(gw['id'])

    def handle_delete(self):
            return True

    def _show_resource(self):
        return self._get_client().show_nuage_gateway(
            self.resource_id)['nuage_gateway']

    def check_delete_complete(self, res):
        return True

    def check_create_complete(self, *args):
        return True


class NuageGatewayPort(neutron.NeutronResource):
    """
    A resource representing Nuage gateway port
    """

    support_status = support.SupportStatus(version='2015.1')

    PROPERTIES = (
        NAME,
        GATEWAY,
    ) = (
        'name',
        'gateway',
    )

    ATTRIBUTES = (
        NAME_ATTR,
        PHYSICAL_NAME_ATTR,
        STATUS_ATTR,
        USERMNEMONIC_ATTR,
        TENANT_ID_ATTR,
        VLAN_RANGES_ATTR,
        SHOW,
    ) = (
        'name',
        'physicalname',
        'status',
        'usermnemonic',
        'tenant_id',
        'vlan',
        'show',
    )

    properties_schema = {
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Canonical name of the physical switch port.'),
            required=True,
            update_allowed=False
        ),
        GATEWAY: properties.Schema(
            properties.Schema.STRING,
            _('Name or UUID of the gateway this port belongs to.'),
            constraints=[
                constraints.CustomConstraint('nuage_gateway.gateway')
            ],
            required=True,
            update_allowed=False
        ),
    }

    attributes_schema = {
        NAME_ATTR: attributes.Schema(
            _("Canonical name of the physical gateway port.")
        ),
        PHYSICAL_NAME_ATTR: attributes.Schema(
            _("Physical name of the gateway port.")
        ),
        STATUS_ATTR: attributes.Schema(
            _("Gateway port status.")
        ),
        USERMNEMONIC_ATTR: attributes.Schema(
            _("User defined gateway port name.")
        ),
        TENANT_ID_ATTR: attributes.Schema(
            _('Tenant owning gateway port.')
        ),
        VLAN_RANGES_ATTR: attributes.Schema(
            _("List of the vlan ranges, supported by this port.")
        ),
        SHOW: attributes.Schema(
            _("All attributes.")
        ),
    }

    def _get_client(self):
        return self.neutron()

    def validate(self):
        super(NuageGatewayPort, self).validate()

    def handle_create(self):
        props = self.prepare_properties(
            self.properties,
            self.physical_resource_name())

        port_list = self._get_client().list_nuage_gateway_ports(
            **props)['nuage_gateway_ports']
        entry = next((item for item in port_list
                     if item['name'] == props['name']), None)
        if entry is None:
            raise exception.ResourceNotAvailable(resource_name=props['name'])
        port = self._get_client().show_nuage_gateway_port(
            entry['id'])['nuage_gateway_port']
        self.resource_id_set(port['id'])

    def handle_delete(self):
        return True

    def _show_resource(self):
        return self._get_client().show_nuage_gateway_port(
            self.resource_id)['nuage_gateway_port']

    def check_delete_complete(self, res):
        return True

    def check_create_complete(self, *args):
        return True


class NuageGatewayPortVlan(neutron.NeutronResource):
    """
    A resource representing Nuage VLAN under Gateway Port.
    """

    support_status = support.SupportStatus(version='2015.1')

    PROPERTIES = (
        GATEWAYPORT,
        VALUE,
    ) = (
        'gatewayport',
        'value',
    )

    ATTRIBUTES = (
        GATEWAY_ATTR,
        GATEWAYPORT_ATTR,
        STATUS_ATTR,
        USERMNEMONIC_ATTR,
        VALUE_ATTR,
        TENANT_ID_ATTR,
        VPORT_ATTR,
        SHOW,
    ) = (
        'gateway',
        'gatewayport',
        'status',
        'usermnemonic',
        'value',
        'tenant_id',
        'vport',
        'show',
    )

    properties_schema = {
        GATEWAYPORT: properties.Schema(
            properties.Schema.STRING,
            _('ID of the gateway port to create vlan on.'),
            constraints=[
                constraints.CustomConstraint('nuage_gateway.gatewayport')
            ],
            required=True,
            update_allowed=False
        ),
        VALUE: properties.Schema(
            properties.Schema.NUMBER,
            _('virtual LAN VID value.'),
            required=True,
            update_allowed=False,
            constraints=[
                constraints.Range(0, 4095)
            ],
        ),
    }

    attributes_schema = {
        GATEWAY_ATTR: attributes.Schema(
            _('ID of the gateway holding VLAN.')
        ),
        GATEWAYPORT_ATTR: attributes.Schema(
            _('ID of the gateway port holding VLAN.')
        ),
        STATUS_ATTR: attributes.Schema(
            _('Status of the VLAN.')
        ),
        USERMNEMONIC_ATTR: attributes.Schema(
            _('User defined mnemonic of the VLAN.')
        ),
        VALUE_ATTR: attributes.Schema(
            _('value of VLAN.')
        ),
        TENANT_ID_ATTR: attributes.Schema(
            _('Tenant owning VLAN.')
        ),
        VPORT_ATTR: attributes.Schema(
            _('ID of the VPort attached to this VLAN.')
        ),
        SHOW: attributes.Schema(
            _('All attributes.')
        ),
    }

    def _get_client(self):
        return self.neutron()

    def _is_built(self, attributes):
        status = attributes['status']
        if status in ('INITIALIZED', 'READY'):
            return True
        elif status == 'MISMATCH':
            raise resource.ResourceInError(
                resource_status=status)
        else:
            raise resource.ResourceUnknownStatus(
                resource_status=status,
                result=_('Resource is not built'))

    def _validate_vlan(self):
        gw_port = self._get_client().show_nuage_gateway_port(
            self.properties.get(self.GATEWAYPORT))['nuage_gateway_port']
        vlan = self.properties.get(self.VALUE)
        vlan_ranges = list(
            range.split('-') for range in gw_port['vlan'].split(','))
        for range in vlan_ranges:
            if int(vlan) >= int(range[0]) and int(vlan) <= int(range[1]):
                return
        msg = _('Vlan is out of range, supported by port')
        raise exception.StackValidationFailed(message=msg)

    def validate(self):
        super(NuageGatewayPortVlan, self).validate()

    def handle_create(self):
        self._validate_vlan()
        props = self.prepare_properties(
            self.properties,
            self.physical_resource_name())
        vlan = self._get_client().create_nuage_gateway_vlan(
            {'nuage_gateway_vlan': props})['nuage_gateway_vlan']
        self.resource_id_set(vlan['id'])

    def handle_delete(self):
        try:
            self._get_client().delete_nuage_gateway_vlan(self.resource_id)
        except Exception as ex:
            self.client_plugin().ignore_not_found(ex)
        else:
            return True

    def _show_resource(self):
        return self._get_client().show_nuage_gateway_vlan(
            self.resource_id)['nuage_gateway_vlan']

    def check_create_complete(self, *args):
        attributes = self._show_resource()
        return self._is_built(attributes)


class NuageGatewayVport(neutron.NeutronResource):
    """
    A resource representing Nuage VPort in Neutron.
    """

    support_status = support.SupportStatus(version='2015.1')

    PROPERTIES = (
        VLAN,
        SUBNET,
        PORT,
        TENANT,
    ) = (
        'gatewayvlan',
        'subnet',
        'port',
        'tenant',
    )

    ATTRIBUTES = (
        GATEWAYPORT_ATTR,
        SUBNET_ATTR,
        PORT_ATTR,
        INTERFACE_ATTR,
        TENANT_ID_ATTR,
        TYPE_ATTR,
        SHOW,
    ) = (
        'gatewayport',
        'subnet',
        'port',
        'interface',
        'tenant_id',
        'type',
        'show',
    )

    properties_schema = {
        VLAN: properties.Schema(
            properties.Schema.STRING,
            _('ID of the VLAN to create Vport on.'),
            constraints=[
                constraints.CustomConstraint('nuage_gateway.gatewayportvlan')
            ],
            required=True,
            update_allowed=False
        ),
        SUBNET: properties.Schema(
            properties.Schema.STRING,
            _('ID of the neutron subnet in case of BRIDGE VPort.'),
            required=False,
            update_allowed=False,
        ),
        PORT: properties.Schema(
            properties.Schema.STRING,
            _('ID of the neutron port in case of HOST VPort.'),
            required=False,
            update_allowed=False,
        ),
        TENANT: properties.Schema(
            properties.Schema.STRING,
            _('ID of the tenant this VPort will belong to.'),
            required=True,
            update_allowed=False,
        ),
    }

    attributes_schema = {
        GATEWAYPORT_ATTR: attributes.Schema(
            _('ID of the Gateway Port  this VPort is created on.')
        ),
        SUBNET_ATTR: attributes.Schema(
            _('Neutron subnet this VPort is created in.')
        ),
        PORT_ATTR: attributes.Schema(
            _('Corresponding neutron port.')
        ),
        INTERFACE_ATTR: attributes.Schema(
            _('ID of the HOST/BRIDGE Interfaces created.')
        ),
        TYPE_ATTR: attributes.Schema(
            _('Type of the VPort created.')
        ),
        TENANT_ID_ATTR: attributes.Schema(
            _('Tenant owning VPort.')
        ),
        SHOW: attributes.Schema(
            _('All attributes.')
        ),
    }

    def _get_client(self):
        return self.neutron()

    def _validate_vport_type(self):
        subnet = self.properties[self.SUBNET]
        port = self.properties[self.PORT]
        if subnet and port:
            raise exception.ResourcePropertyConflict(
                self.SUBNET, self.PORT)
        if subnet is None and port is None:
            msg = _('Either port or subnet must be specified')
            raise exception.StackValidationFailed(message=msg)

    def validate(self):
        super(NuageGatewayVport, self).validate()
        self._validate_vport_type()

    def handle_create(self):
        props = self.prepare_properties(
            self.properties,
            self.physical_resource_name())
        vport = self._get_client().create_nuage_gateway_vport(
            {'nuage_gateway_vport': props})['nuage_gateway_vport']
        self.resource_id_set(vport['id'])

    def handle_delete(self):
        try:
            self._get_client().delete_nuage_gateway_vport(self.resource_id)
            body = {
                'nuage_gateway_vlan': {
                    'action': 'unassign',
                    'tenant': self.properties.get(self.TENANT)
                }
            }
            self._get_client().update_nuage_gateway_vlan(
                self.properties.get(self.VLAN), body)
        except Exception as ex:
            self.client_plugin().ignore_not_found(ex)
        else:
            return True

    def _show_resource(self):
        return self._get_client().show_nuage_gateway_vport(
            self.resource_id)['nuage_gateway_vport']


def resource_mapping():
    return {
        'Nuage::Neutron::Gateway': NuageGateway,
        'Nuage::Neutron::GatewayPort': NuageGatewayPort,
        'Nuage::Neutron::GatewayPortVlan': NuageGatewayPortVlan,
        'Nuage::Neutron::GatewayVport': NuageGatewayVport,
    }


def constraint_mapping():
    return {
        'nuage_gateway.gateway': GatewayConstraint,
        'nuage_gateway.gatewayport': GatewayPortConstraint,
        'nuage_gateway.gatewayportvlan': GatewayPortVlanConstraint,
    }
