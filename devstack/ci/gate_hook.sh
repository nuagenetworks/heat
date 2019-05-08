#! /bin/bash

# Copyright 2018 Nokia
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# Inject config into local.conf
function set_local_conf {
    local GATE_DEST=$BASE/new
    local DEVSTACK_PATH=$GATE_DEST/devstack
    local LOCAL_CONF=$DEVSTACK_PATH/local.conf
    cat << EOF | tee -a $LOCAL_CONF
[[post-config|\$NOVA_CONF]]
[DEFAULT]
security_group_api = neutron
[neutron]
ovs_bridge = alubr0
[[test-config|\$TEMPEST_CONFIG]]
[nuage_sut]
nuage_pat_legacy=disabled
EOF
}

export DEVSTACK_LOCAL_CONFIG+=$'\n'"TEMPEST_RUN_VALIDATION=True"
# Note the actual url here is somewhat irrelevant because it
# caches in nodepool, however make it a valid url for
# documentation purposes.
export DEVSTACK_LOCAL_CONFIG="enable_plugin nuage-openstack-neutron git://git.openstack.org/openstack/nuage-openstack-neutron"

# Enable Nuage specifics
export DEVSTACK_LOCAL_CONFIG+=$'\n'"enable_plugin nuage-openstack-neutronclient git://git.openstack.org/openstack/nuage-openstack-neutronclient"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"NUAGE_FIP_UNDERLAY=True"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"OVS_BRIDGE=alubr0"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"Q_USE_PROVIDERNET_FOR_PUBLIC=False"

# VSP related config
export DEVSTACK_LOCAL_CONFIG+=$'\n'"NUAGE_VSD_SERVERS=$VSD_SERVER"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"NUAGE_VSD_DEF_NETPART_NAME=DevstackCI-${ZUUL_CHANGE}-${job}-${RANDOM}"

# Keep localrc to be able to set some vars in pre_test_hook
export KEEP_LOCALRC=1

# Neutron Plugin related config
export DEVSTACK_LOCAL_CONFIG+=$'\n'"Q_PLUGIN=ml2"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"Q_ML2_PLUGIN_EXT_DRIVERS=nuage_subnet,nuage_port,port_security,nuage_network"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"Q_ML2_TENANT_NETWORK_TYPE=vxlan,vlan"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"ENABLE_TENANT_TUNNELS=True"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"ML2_VLAN_RANGES=physnet1:1:4000,physnet2:1:4000"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"PHYSICAL_NETWORK=physnet1,physnet2"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"Q_ML2_PLUGIN_MECHANISM_DRIVERS=nuage,nuage_sriov,nuage_baremetal"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"Q_ML2_PLUGIN_TYPE_DRIVERS=vxlan,vlan"

# Enable Heat
export DEVSTACK_LOCAL_CONFIG+=$'\n'"enable_plugin heat git://git.openstack.org/openstack/heat.git"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"enable_plugin nuage-heat  git://git.openstack.org/openstack/heat.git"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"TEMPEST_PLUGINS=\"heat-tempest-plugin $BASE/new/nuage-tempest-plugin\""
# disable neutron advanced services for nuage ci
export DEVSTACK_LOCAL_CONFIG+=$'\n'"disable_service q-lbaas q-fwaas q-vpn"

# nuage tempest plugin related
export DEVSTACK_LOCAL_CONFIG+=$'\n'"enable_plugin nuage-tempest-plugin git://git.openstack.org/openstack/nuage-tempest-plugin"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"NUAGE_PLUGIN_MODE=ml2"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"NUAGE_VSP_RELEASE=$VSP_RELEASE"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"NUAGE_OPENSTACK_RELEASE=$NUAGE_OS_RELEASE"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"NUAGE_CONTROLLER_PSSWD=root"

# We are only interested on Neutron and Heat, so very few services are needed
# to deploy devstack and run the tests
s=""
s+="mysql,rabbit"
s+=",key"
s+=",n-api,n-cond,n-cpu,n-crt,n-sch,placement-api"
s+=",g-api,g-reg"
s+=",q-svc,quantum"
s+=",tempest"
s+=",dstat"

export OVERRIDE_ENABLED_SERVICES="$s"

export DEVSTACK_GATE_TEMPEST_ALL_PLUGINS=0
export DEVSTACK_GATE_CONFIGDRIVE=1
export DEVSTACK_GATE_LIBVIRT_TYPE=kvm


# We need to configure tempest for heat, so
# gate hook will not run tempest, tempest
# will be launched from post_hook.
export DEVSTACK_GATE_TEMPEST_NOTESTS=1

# Explicitly set LOGDIR to align with the SCREEN_LOGDIR setting
# from devstack-gate.  Otherwise, devstack infers it from LOGFILE,
# which is not appropriate for our gate jobs.
export DEVSTACK_LOCAL_CONFIG+=$'\n'"LOGDIR=$BASE/new/screen-logs"

set_local_conf

$BASE/new/devstack-gate/devstack-vm-gate.sh

