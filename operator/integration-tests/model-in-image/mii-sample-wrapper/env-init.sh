# Copyright (c) 2019, 2021, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

# This file sets the defaults for the sample wrapper scripts, 
# and does other actions that are common to all of the sample's scripts.

WORKDIR=${WORKDIR:-/tmp/$USER/model-in-image-sample-work-dir}

SCRIPTDIR="$( cd "$(dirname "$0")" > /dev/null 2>&1 ; pwd -P )"
SRCDIR="$( cd "$SCRIPTDIR/../../../.." > /dev/null 2>&1 ; pwd -P )"
MIISAMPLEDIR="$( cd "$SRCDIR/kubernetes/samples/scripts/create-weblogic-domain/model-in-image" > /dev/null 2>&1 ; pwd -P )"

WDT_DOMAIN_TYPE=${WDT_DOMAIN_TYPE:-WLS}
IMAGE_TYPE=${IMAGE_TYPE:-$WDT_DOMAIN_TYPE}

if    [ ! "$WDT_DOMAIN_TYPE" = "WLS" ] \
   && [ ! "$WDT_DOMAIN_TYPE" = "RestrictedJRF" ] \
   && [ ! "$WDT_DOMAIN_TYPE" = "JRF" ]; then
  echo "@@ Error: Invalid domain type WDT_DOMAIN_TYPE '$WDT_DOMAIN_TYPE': expected 'WLS', 'JRF', or 'RestrictedJRF'."
  exit 1
fi

if    [ ! "$IMAGE_TYPE" = "WLS" ] \
   && [ ! "$IMAGE_TYPE" = "WLS-AI" ] \
   && [ ! "$IMAGE_TYPE" = "RestrictedJRF" ] \
   && [ ! "$IMAGE_TYPE" = "JRF" ] \
   && [ ! "$IMAGE_TYPE" = "JRF-AI" ]; then
  echo "@@ Error: Invalid image type IMAGE_TYPE '$IMAGE_TYPE': expected 'WLS', 'WLS-AI', 'JRF', 'JRF-AI' or 'RestrictedJRF'."
  exit 1
fi

DOMAIN_UID=${DOMAIN_UID:-sample-domain1}
DOMAIN_NAMESPACE=${DOMAIN_NAMESPACE:-sample-domain1-ns}
CUSTOM_DOMAIN_NAME=${CUSTOM_DOMAIN_NAME:-domain1}

DOMAIN_RESOURCE_TEMPLATE="${DOMAIN_RESOURCE_TEMPLATE:-mii-domain.yaml.template-$IMAGE_TYPE}"
DOMAIN_RESOURCE_FILENAME="${DOMAIN_RESOURCE_FILENAME:-domain-resources/mii-${DOMAIN_UID}.yaml}"

DB_NAMESPACE=${DB_NAMESPACE:-default}

DOWNLOAD_WIT=${DOWNLOAD_WIT:-when-missing}
DOWNLOAD_WDT=${DOWNLOAD_WDT:-when-missing}
WDT_INSTALLER_URL=${WDT_INSTALLER_URL:-https://github.com/oracle/weblogic-deploy-tooling/releases/latest}
WIT_INSTALLER_URL=${WIT_INSTALLER_URL:-https://github.com/oracle/weblogic-image-tool/releases/latest}

if [[ "$WDT_DOMAIN_TYPE" = "WLS" || "$WDT_DOMAIN_TYPE" = "WLS-AI" ]]; then
  defaultBaseImage="container-registry.oracle.com/middleware/weblogic"
else
  defaultBaseImage="container-registry.oracle.com/middleware/fmw-infrastructure"
fi

BASE_IMAGE_NAME="${BASE_IMAGE_NAME:-$defaultBaseImage}"
BASE_IMAGE_TAG=${BASE_IMAGE_TAG:-12.2.1.4}
BASE_IMAGE="${BASE_IMAGE_NAME}:${BASE_IMAGE_TAG}"

MODEL_IMAGE_NAME=${MODEL_IMAGE_NAME:-model-in-image}
MODEL_IMAGE_TAG=${MODEL_IMAGE_TAG:-${IMAGE_TYPE}-v1}
MODEL_IMAGE="${MODEL_IMAGE_NAME}:${MODEL_IMAGE_TAG}"
MODEL_IMAGE_BUILD=${MODEL_IMAGE_BUILD:-always}
MODEL_DIR=${MODEL_DIR:-model-images/model-in-image__${MODEL_IMAGE_TAG}}
AUXILIARY_IMAGE_PATH=${AUXILIARY_IMAGE_PATH:-/auxiliary}
WDT_MODEL_HOME=${WDT_MODEL_HOME:-${AUXILIARY_IMAGE_PATH}/models}
WDT_INSTALL_HOME=${WDT_INSTALL_HOME:-${AUXILIARY_IMAGE_PATH}/weblogic-deploy}
AUXILIARY_IMAGE_DOCKER_FILE_SOURCEDIR=${AUXILIARY_IMAGE_DOCKER_FILE_SOURCEDIR:-ai-docker-file}

IMAGE_PULL_SECRET_NAME=${IMAGE_PULL_SECRET_NAME:-""}

ARCHIVE_SOURCEDIR=${ARCHIVE_SOURCEDIR:-archives/archive-v1}

INCLUDE_MODEL_CONFIGMAP=${INCLUDE_MODEL_CONFIGMAP:-false}
CORRECTED_DATASOURCE_SECRET=${CORRECTED_DATASOURCE_SECRET:-false}

INTROSPECTOR_DEADLINE_SECONDS=${INTROSPECTOR_DEADLINE_SECONDS:-300}

echo "@@"
echo "@@ ######################################################################"
[ $# -eq 0 ] && echo "@@ Info: Running '$(basename "$0")'"
[ $# -ne 0 ] && echo "@@ Info: Running '$(basename "$0") $@'"
echo "@@ Info: WORKDIR='$WORKDIR'."
echo "@@ Info: SCRIPTDIR='$SCRIPTDIR'."
echo "@@ Info: MIISAMPLEDIR='$MIISAMPLEDIR'."
echo "@@ Info: DOMAIN_UID='$DOMAIN_UID'."
echo "@@ Info: DOMAIN_NAMESPACE='$DOMAIN_NAMESPACE'."

