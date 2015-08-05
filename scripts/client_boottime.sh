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

mkdir -p /var/run/wesentropy
chmod 777 /var/run/wesentropy

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
parentdir="$(dirname "$dir")"

# Install QRNG kernel driver.
if ! ( lsmod | grep -q dmadriver ); then
    insmod "${parentdir}/bin/3.10.0-229.el7.x86_64/dmadriver.ko"
fi
