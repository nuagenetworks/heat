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


from heat.common.i18n import _
from heat.engine import attributes
from heat.engine import properties
from heat.engine.resources.openstack.neutron import neutron
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


class NetPartition(neutron.NeutronResource):
    """
    A resource representing Nuage Netpartition in Neutron.
    """
    PROPERTIES = (
        NAME,
    ) = (
        "name",
    )

    ATTRIBUTES = (
        NAME_ATTR,
        TENANT_ID,
    ) = (
        "name",
        "tenant_id",
    )

    properties_schema = {
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('The name of the Netpartition.'),
            required=True,
            update_allowed=False
        ),
    }

    attributes_schema = {
        NAME_ATTR: attributes.Schema(
            _("Friendly name of the Netpartition.")
        ),
        TENANT_ID: attributes.Schema(
            _('Tenant owning the Netpartition.')
        ),
    }

    def prepare_properties(self, properties, name):
        props = super(NetPartition, self).prepare_properties(
            properties, name
        )
        return props

    def handle_create(self):
        props = self.prepare_properties(
            self.properties, self.physical_resource_name())
        nuage_netpartition = self.neutron_client().create_net_partition(
            {'net_partition': props})['net_partition']
        self.resource_id_set(nuage_netpartition['id'])

    def handle_delete(self):
        client = self.neutron_client()
        try:
            client.delete_net_partition(self.resource_id)
        except Exception as ex:
            self.client_plugin('neutron').ignore_not_found(ex)

    def _show_resource(self):
        return self.neutron_client().show_net_partition(
            self.resource_id)['net_partition']

    def neutron_client(self):
        return self.neutron()


def resource_mapping():
    return {
        'Nuage::Neutron::Netpartition': NetPartition,
    }
