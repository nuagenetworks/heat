# Heat resources providing Nuage VSP extensions
The resources and configuration in this module are for using Heat with Nuage VSP. These resources either
allow using Nuage VSP services that don't have equivalent services in OpenStack or account for differences between
a generic OpenStack deployment and one with Nuage VSP integration.

## Setup

### 1. Install the Nuage plugins in Heat

**NOTE**: These instructions assume the value of heat.conf plugin_dirs includes the
default directory /usr/lib/heat.

To install the plugin, from this directory run:
`sudo python ./setup.py install --prefix=/usr`

### 2. Restart heat

Only the process "heat-engine" needs to be restarted to load the newly installed
plugin.


## Resources

The following Resources are provided:

- Nuage Netpartition resource
    - Nuage::Neutron::Netpartition
    - Nuage::Neutron::ProjectNetpartitionMapping
- Nuage Gateway resources
    - Nuage::Neutron::Gateway
    - Nuage::Neutron::GatewayPort
    - Nuage::Neutron::GatewayPortVlan
    - Nuage::Neutron::GatewayVport
- Nuage Security Group resource
    - Nuage::Neutron::SecurityGroup
- Nuage Redirect Target resources
    - Nuage::Neutron::RedirectTarget
    - Nuage::Neutron::RedirectTargetRule
    - Nuage::Neutron::RedirectTargetVIP



## Usage

For each of the resources, example heat templates are provided.
See [nuage-heat/heat-templates/hot](nuage-heat/heat-templates/hot).

