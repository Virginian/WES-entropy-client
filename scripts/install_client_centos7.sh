#!/bin/bash

# Copyright 2014-2015 Whitewood Encryption Systems, Inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
# set -x

yum -y update
yum -y install epel-release
yum -y update

yum -y install gcc
yum -y install python-pip
yum -y install protobuf-python
yum -y install python-devel
yum -y install protobuf-compiler
yum -y install openssl-devel

pip install python-daemon==2.0.5 lockfile==0.10.2 ipdb==0.8 enum==0.4.4 \
  tornado==4.1 pymongo==2.8.0 motor==0.4 pycrypto==2.6.1

conf_dir="/etc/wesentropy"

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
parentdir="$(dirname "$dir")"

# Make QRNG Fifo server
make -C "${parentdir}/src-c/wesqrngd" -f Makefile.wesqrngd

# Generate python classes from protobuf spec
enginedir="${parentdir}/src-python/WesEntropy/Engine"
protoc "-I=${enginedir}" "--python_out=${enginedir}" "${enginedir}/eaas.proto"

# Make config directory and set permissions.
if [[ ! -d "${conf_dir}" ]]; then
    mkdir -p "${conf_dir}"
fi;
chmod 755 "${conf_dir}"

# Copy configs into config directory.
source_conf_dir="${parentdir}/conf"
target_client_conf="${conf_dir}/client.conf"

cp "${source_conf_dir}/client.conf" "${target_client_conf}"
chmod 644 "${target_client_conf}"

cd "${parentdir}/openssl"
make -C libwesentropy -f Makefile.wesentropy

cd "${parentdir}/openssl/ewes"
make

mkdir -p /var/run/wesentropy
chmod 777 /var/run/wesentropy

# Install QRNG kernel driver.
if ! ( lsmod | grep -q dmadriver ); then
    insmod "${parentdir}/bin/3.10.0-229.el7.x86_64/dmadriver.ko"
fi

echo "Finished running $0."

exit 0
