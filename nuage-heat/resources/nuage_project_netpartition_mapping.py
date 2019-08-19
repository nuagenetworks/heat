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


class ProjectNetpartitionMapping(neutron.NeutronResource):
    """
    A resource representing Nuage Project to Netpartition mapping in Neutron.
    """
    PROPERTIES = (
        PROJECT, NETPARTITIONID
    ) = (
        'project', 'net_partition_id'
    )

    ATTRIBUTES = (
        PROJECTATTR, NETPARTITIONID_ATTR
    ) = (
        'project', 'net_partition_id'
    )

    properties_schema = {
        PROJECT: properties.Schema(
            properties.Schema.STRING,
            _('Project ID.'),
            required=True,
            update_allowed=False
        ),
        NETPARTITIONID: properties.Schema(
            properties.Schema.STRING,
            _('Netpartition ID.'),
            required=True,
            update_allowed=False
        ),
    }

    attributes_schema = {
        PROJECTATTR: attributes.Schema(
            _("ID of the Project.")
        ),
        NETPARTITIONID_ATTR: attributes.Schema(
            _("ID of the Netpartition.")
        ),
    }

    def prepare_properties(self, properties, name):
        props = super(ProjectNetpartitionMapping, self).prepare_properties(
            properties, name
        )
        return props

    def handle_create(self):
        props = self.prepare_properties(
            self.properties, self.physical_resource_name())
        mapping = (
            self.neutron_client().create_project_net_partition_mapping(
                {'project_net_partition_mapping': props}
            )['project_net_partition_mapping'])
        self.resource_id_set(mapping['project'])

    def handle_delete(self):
        client = self.neutron_client()
        try:
            client.delete_project_net_partition_mapping(self.resource_id)
        except Exception as ex:
            self.client_plugin('neutron').ignore_not_found(ex)

    def _show_resource(self):
        return self.neutron_client().show_project_net_partition_mapping(
            self.resource_id)['project_net_partition_mapping']

    def neutron_client(self):
        return self.neutron()


def resource_mapping():
    return {
        'Nuage::Neutron::ProjectNetpartitionMapping':
            ProjectNetpartitionMapping,
    }
