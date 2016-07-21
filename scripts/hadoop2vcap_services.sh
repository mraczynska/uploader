#!/bin/bash

# Copyright (c) 2016 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Validate arguments
if [ -z ${CORE_SITE_XML+x} ]; then
  echo "CORE_SITE_XML variable must be set!"
  exit 1
fi

if [ -z ${HDFS_SITE_XML+x} ]; then
  echo "HDFS_SITE_XML variable must be set!"
  exit 1
fi

# Get this script location, so that it could be executed from anywhere
SCRIPT_DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]}))

# File for a temporary result
JSON_FILE=$(mktemp --suffix .json)

# Transform XML into JSON
echo $CORE_SITE_XML | xalan -xsl $SCRIPT_DIR/hadoop2json.xsl > $JSON_FILE
echo $HDFS_SITE_XML | xalan -xsl $SCRIPT_DIR/hadoop2json.xsl >> $JSON_FILE

# 'Merge' JSON objects
HADOOP_CONFIG_JSON=$(jq -s add $JSON_FILE)

# Make the variable available for envsubst
export HADOOP_CONFIG_JSON

# Clean up 
rm $JSON_FILE

# Render VCAP_SERVICES template
cat $SCRIPT_DIR/vcap_template.json | envsubst
