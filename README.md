# Whitewood Entropy Management for OpenSSL

## What is the Whitewood Entropy Management for OpenSSL agent?
The [OpenSSL cryptographic library](https://www.openssl.org/) is one of the most widely deployed cryptographic libraries in the world, estimated to be used by two-thirds of all webservers. However, despite its popularity OpenSSL lacks many of the management capabilities that are normally associated with commercial security tools. The challenge of managing entropy in OpenSSL is particularly clear given the almost infinite combination of operating systems and hardware platforms that it supports. This raises important questions about security in real-world settings, particularly those that suffer from few physical sources of entropy or where numerous applications compete for the same limited supply of random data.

The Whitewood Entropy Management for OpenSSL agent addresses this issue by enabling the user to configure OpenSSL deployments to select and combine specific sources of entropy, measure the consumption of entropy, and decide when and how to use a NIST-compliant DRBG (Deterministic Random Bit Generator) that is included in the package. The Whitewood agent requires no modification to the standard OpenSSL library and includes full support for Whitewood’s Entropy Engine, a quantum-powered random number generator that can be deployed locally or accessed over a network as a shared resource as well as other entropy sources such as Intel's CPU based random number generator, RdRand.

### Component Overview:
The Whitewood Entropy Management for OpenSSL agent (refered to as WESentropy) is comprised of three main components: the WESentropy daemon, the WESentropy client, and the WESentropy stats.

#### WESentropy Daemon:
The WESentropy daemon is a centralized entropy collection and management program used to collect entropy from user specified sources and distribute it to any client connected to the daemon.

#### WESentropy Client:
The WESentropy client comes in two forms: a standalone client and an OpenSSL engine, used to integrate with OpenSSL. In either setup the client connects to the locally running WESentropy daemon and requests random data. In the case of the standalone client this random data is requested via STDIN and is output to STDOUT. In the case of the OpenSSL engine this random data is requested and used by OpenSSL to perform its tasks such as key generation or handling SSL connections.

#### WESentropy Stats:
The WESentropy stats is a command line utility for queuing stats from the WESentropy daemon on the generation and consumption of entropy in the system along with a few other useful statistics such as uptime.

## Installation:
An installation script has been provided in this repository that has been tested on a clean CentOS 7 VM.

* CentOS 7: [OS Boxes CentOS 7.1-1503](http://sourceforge.net/projects/osboxes/files/vms/vmware/CentOS/7.1/CentOS_7.1_1503-%2864bit%29.7z/download)

As root, simply run:

```bash
WES-entropy-client/scripts/install_client_centos7.sh
```

## Configuration:
The strength of the WESentropy system is its configurability. The WESentropy system allows the end user to configure which entropy sources the system uses, and how it uses those sources.

The WESEntropy system uses two kinds of entropy sources, ```stream source``` and ```seed source```, and uses them in the following construction where at least one entropy source is required:

```
seed source      stream source
     |                |
     |                |
     v                v
    DRBG -----------> +
                      |
                      |
                      v
```

The stream and seed sources along with the DRBG configuration and a few other options are defined in the configuration file, which is located at ```/etc/wesentropy/client.conf``` by default.

The configuration file contains five sections, each described below.

### DEFAULT:
The default section contains only one option, ```working_dir```, which specifies the working director for the WESentropy daemon.

### daemon:
The daemon section contains only one option, ```socket_path```, which specifies the path to the socket that is used to connect clients to the daemon.

### seed_source:
The seed_source section contains one value, ```seed_source1```, which describes an entropy source that will be used as a seed for the DRBG as shown in the construction above. These entropy sources can follow one of five forms:
- ```None``` - Specifies that no source will be used.
- ```('FILE', '/path/to/file', Prediction_Resistance)``` - Specifies a device file where ```/path/to/file``` is the path to a device file that outputs entropy, for example '/dev/urandom', and Prediction Resistance is either True or False based on whether or not the entropy source provides prediction resistance, as defined in NIST SP800-90A.
- ```('HARDWARE', 'RDRAND', True)``` - Specifies Intel's CPU based DRBG, RdRand.
- ```('HARDWARE', 'QRNG', 'QRNG Number')``` - Specifies a WES QRNG card where 'QRNG Number' is '0', '1', '2', or '3', specifying which attached QRNG card is being used. For more information on WES QRNG cards, please visit [Whitewood Encryption Systems](http://www.whitewoodencryption.com/).
- ```('ENTROPY SERVER', 'URI', 'CLIENT_UUID', 'CLIENT_BASE64_KEY')``` - Specifies a WES Entropy as a Service System, where 'URI' is the URI of the entropy server, 'CLIENT_UUID' is the UUID to be used by this client, and 'CLIENT_BASE64_KEY' is the client's key. **The WES Entropy as a Service System is currently in development and not yet available to consumers, for more information please visit [Whitewood Encryption Systems](http://www.whitewoodencryption.com/).**

### stream_source:
The stream_source section contains one value, ```stream_source1```, which describes an entropy source that will be used as a stream source as shown in the construction above. These entropy sources can be one of five forms described in the ```seed_source``` section.

### drbg:
The drbg section contains two options, ```drbg_spec``` and ```reseed_rate```.

The ```drbg_spec``` option defines the DRBG type, algorithm, and security strength of the DRBG used in the WESentropy system. The value of ```drbg_spec``` follows the form ```<drbg_type>_DRBG_<algorithm>_<security_strength>```, where:
- ```<drbg_type>``` can be 'CTR' or 'HASH'
- If ```<drbg_type>``` is 'CTR', then:
  - ```<algorithm>``` must be 'AES'
  - ```<security_strength>``` can be 112, 128, 192, or 256
- If ```<drbg_type>``` is 'HASH', then:
  - ```<algorithm>``` must be one of 'SHA1', 'SHA224', 'SHA256', 'SHA384', or 'SHA512'
  - Possible values for ```<security_strength>``` depend on the algorithm chosen:
    - SHA1 - 80
    - SHA224 - 80, 128, 192
    - SHA256 - 80, 128, 192, 256
    - SHA384 - 80, 128, 192, 256
    - SHA512 - 80, 128, 192, 256

The ```reseed_rate``` option defines the DRBG reseed rate and can be one of three values:
- ```LINESPEED``` - Reseed the DRBG after every request for random bits.
- ```MINIMAL``` - Reseed only as often as required by NIST SP800-90A.  
- ```n``` - Reseed the DRBG after every n requests for random bits, where n is a positive integer.

An example configuration is as follows:
```
[DEFAULT]
working_dir: /var/run/wesentropy

[daemon]
socket_path: %(working_dir)s/wes.socket

[seed_source]
seed_source1: ('FILE', '/dev/urandom', False)

[stream_source]
stream_source1: ('HARDWARE', 'QRNG', True)

[drbg]
drbg_spec:   Hash_DRBG_SHA256_256
reseed_rate: LINESPEED
```

### To run:

1. In one window, start the WESentropy daemon:

    ```bash
    WES-entropy-client/scripts/wesentropyd.sh
    ```

2. In another window, start the WESentropy client:

    ```bash
    WES-entropy-client/scripts/wesentropyclient.sh
    ```

3. In order to view statistics on the system, in a third window, run the WESentropy stats program:
    ```bash
    WES-entropy-client/scripts/wesentropystats.sh
    ```

### Boot Script
When the machine that WESentropy is installed on is restarted a few things must occur before WESentropy can be run.

The directory ```/var/run/wesentropy``` must be created and set to the appropriate permissions (read/write/execute for the user running WESentropy), and if running with the QRNG card, the QRNG kernel module must be loaded.

In order to do this, a script has been provided with this repository called ```client_boottime.sh```. This script will create the required directory and load the QRNG kernel module. This script can be set up to run on reboot by adding it to your ```/etc/rc.local``` script. For more information see the CentOS help page [Running Additional Programs at Boot Time](https://www.centos.org/docs/5/html/Installation_Guide-en-US/s1-boot-init-shutdown-run-boot.html).


## Apache with OpenSSL Integration

It is recommended that a separate installation of OpenSSL is used to interface with the WESentropy system and this guide assumes that that OpenSSL instance is installed to ```/opt/openssl```.

The WESentropy system loads into OpenSSL as an engine, replacing all of OpenSSL's calls to get entropy with calls into the WESentropy system.

### Modify OpenSSL Config
Locate the OpenSSL configuration file, found at ```/opt/openssl/ssl/openssl.cnf```,  and add the following to the default section of the configuration file (before the first [section]).
```
openssl_conf = openssl_def

[openssl_def]
engines = engine_section

[engine_section]
ewes = ewes_section

[ewes_section]
engine_id = ewes
dynamic_path = /path/to/WES-entropy-client/openssl/ewes/libewes.so
default_algorithms = RAND
```

### Modify and Build Apache

The default behavior for OpenSSL when loaded by Apache's mod_ssl is to ignore configuration files. In order to get OpenSSL to read the config file that was just modified, a small source code change is required. In order to download the Apache HTTPD source and modify it the following steps are required:


1. Download the latest Apache HTTPD source code, extract it, and cd into the source's root directory.
2. Download the Apache Portable Runtime: APR, and APR-UTIL. Extract them to srclib/apr and srclib/apr-util respectively.
3. Open the file modules/ssl/mod_ssl.c.
4. Search for the line OpenSSL_add_all_algorithms() and change this to OPENSSL_add_all_algorithms_conf().  Note that the capitalization of OpenSSL is different in these two function names.


Now that the source code has been patched, Apache can be built. There are two options for building and running Apache that both allow for the use of a user-specified OpenSSL instance:

1. Either Apache is configured and compiled with the option --with-ssl=/opt/openssl, or
2. Apache is told which openssl install to use by setting the environment variable LD_LIBRARY_PATH at runtime.

For option 1, build Apache as follows:
```bash
./configure --prefix=/path/to/apache-install --with-ssl=/opt/openssl \
  --with-included-apr --enable-ssl --enable-so --enable-debugger-mode && \
  make && sudo make install
```

For option 2, build Apache as follows:
```bash
./configure --prefix=/path/to/apache-install \
  --with-included-apr --enable-ssl --enable-so --enable-debugger-mode && \
  make && sudo make install
```

Now that Apache is installed, its config files must be edited to enable OpenSSL. Two files must be modified, both located in /path/to/apache-install directory.

#### /path/to/apache-install/config/httpd.conf

Uncomment the following two lines:
```
#LoadModule ssl_module modules/mod_ssl.so
#Include conf/extra/httpd-ssl.conf
```
#### /path/to/apache-install/config/extras/httpd-ssl.conf

Comment out the following two lines:
```
SSLSessionCache        "shmcb:/path/to/apache-install/logs/ssl_scache(512000)"
SSLSessionCacheTimeout  300
```

### Run Apache
#### Start the wesentropyd service:
```bash
scripts/wesentropyd.sh
```

#### Update Environment

In the shell that apache will be started in, set ```PYTHONPATH```:
```bash
export PYTHONPATH=$PYTHONPATH:/path/to/WES-entropy-client/src-python
```

If configured with ```--with-ssl=/opt/openssl```:
```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/WES-entropy-client/openssl/libwesentropy
```
Otherwise:
```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/openssl/lib:/path/to/WES-entropy-client/openssl/libwesentropy
```

Set ```LD_PRELOAD``` to load Python library:
```bash
export LD_PRELOAD=/usr/lib64/libpython2.7.so
```

#### Start Apache's HTTPD'
```bash
/path/to/apache-install/bin/httpd
```

Now Apache will obtain all randomness it requires from the WESentropy system, allowing easy user configuration of entropy sources and combination.

## License

Copyright 2014-2015 Whitewood Encryption Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
