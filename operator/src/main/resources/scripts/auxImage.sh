#!/bin/sh
# Copyright (c) 2021, 2022, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

# Init container script for the auxiliary image feature.
# See 'domain.spec.configuration.model.auxiliaryImages' for details.

# Notes:
# This script purposely tries to exit zero even on failure as
# the Operator monitors the container running this
# script for the Intropector job case, and we have
# seen issues with non-zero exiting scripts.
#
# The operator fails the introspector if it detects an
# ERROR/SEVERE, and succeeds if it detects
# 'executed successfully'.
#
# The main introspector and pod scripts will echo
# the contents of /${AUXILIARY_IMAGE_MOUNT_PATH}/auxiliary-image-logs/
# and fail if they are missing, or if any do not
# include 'executed successfully', or if the scripts
# cannot create (touch) files in /${AUXILIARY_IMAGE_MOUNT_PATH}.
# (See also utils.sh checkAuxiliaryImage function)

scriptDir="$( cd "$(dirname "$0")" > /dev/null 2>&1 ; pwd -P )"

if [ "${debug}" == "true" ]; then set -x; fi;

source ${scriptDir}/utils_base.sh
[ $? -ne 0 ] && echo "[SEVERE] Missing file ${scriptDir}/utils_base.sh" && exit 1
UNKNOWN_SHELL=true

checkEnv AUXILIARY_IMAGE_TARGET_PATH AUXILIARY_IMAGE_CONTAINER_NAME || exit 1

initAuxiliaryImage > /tmp/auxiliaryImage.out 2>&1
cat /tmp/auxiliaryImage.out
mkdir -p ${AUXILIARY_IMAGE_TARGET_PATH}/auxiliaryImageLogs
cp /tmp/auxiliaryImage.out ${AUXILIARY_IMAGE_TARGET_PATH}/auxiliaryImageLogs/${AUXILIARY_IMAGE_CONTAINER_NAME}.out
exit
