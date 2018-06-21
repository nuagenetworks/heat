#!/bin/bash
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

# This script is executed inside post_test_hook function in devstack gate.

set -ex

export DEST=${DEST:-/opt/stack/new}
sudo -E $DEST/heat/heat_integrationtests/prepare_test_env.sh

set -o errexit
if [[ "${TEMPEST_OS_TEST_TIMEOUT:-}" != "" ]] ; then
    TEMPEST_COMMAND="sudo -H -E -u tempest OS_TEST_TIMEOUT=$TEMPEST_OS_TEST_TIMEOUT tox"
else
    TEMPEST_COMMAND="sudo -H -E -u tempest tox"
fi
cd $BASE/new/tempest
echo "Checking installed Tempest plugins:"
$TEMPEST_COMMAND -evenv-tempest -- tempest list-plugins

echo "Running tempest with plugins and a custom regex filter"
$TEMPEST_COMMAND -evenv-tempest -- tempest run --regex '^(heat_tempest_plugin\.tests\.functional\.test_create_update_neutron|nuage_tempest_plugin\.tests\.api\.(orchestration|ipv6\.vsd_managed\.test_orchestration)).*' --concurrency=$TEMPEST_CONCURRENCY


