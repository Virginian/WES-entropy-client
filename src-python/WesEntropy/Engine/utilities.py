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

'''WES Entropy Utilities class'''
import ConfigParser
import logging
import hmac
import struct
import sys
import os
from enum import Enum


class WesEntropyException(Exception):
    """WES Entropy Exception class"""
    pass

def set_log_level():
    """Set log level to DEBUG if we are running verbose tests"""
    log_level = logging.CRITICAL
    if '-v' in sys.argv:
        log_level = logging.DEBUG

    logging.getLogger().setLevel(log_level)
    logging.basicConfig(format='%(threadName)s %(levelname)s: %(message)s',
                        level=log_level)

def binstr_xor(astr, bstr):
    'XOR the bytes of a pair of strings.'

    return ''.join([chr(ord(aa) ^ ord(bb)) for (aa, bb) in zip(astr, bstr)])

def binstr_zeropad(initial, n_bits):
    'Pad a string to the right with null bytes.'

    n_bytes = (n_bits + 7) / 8
    return (initial + '\0' * (n_bytes - len(initial)))[:n_bytes]

def binstr_increment(value, n_bits):
    'Increment a big-endian string modulo a power of two.'

    if value:
        vlist = list(value)
    else:
        vlist = list(binstr_zeropad('', n_bits))
    trailbits = n_bits & 7
    index = n_bits / 8
    if trailbits:
        valbyte = (ord(vlist[index]) + (1 << (8-trailbits))) & 0xff
        vlist[index] = chr(valbyte)
    else:
        valbyte = 0
    index -= 1
    while valbyte == 0 and index >= 0:
        valbyte = (ord(vlist[index]) + 1) & 0xff
        vlist[index] = chr(valbyte)
        index -= 1
    return ''.join(vlist)

def byte_add(abyte, bbyte, carry=0):
    'Add together two bytes, with carry.'
    sumval = ord(abyte) + ord(bbyte) + carry
    return chr(sumval & 0xff), (sumval >> 8)

def binstr_leftmost(vstr, n_bits):
    'Return the leftmost n_bits of a binary string.'

    left = vstr[:n_bits / 8]
    if n_bits & 7:
        last_byte = vstr[n_bits / 8]
        left = left + chr(ord(last_byte) & ~(0xff >> (n_bits & 7)))
    return left

def binstr_add(astr, bstr, n_bits):
    'Add together two big-endian strings modulo a power of two.'

    # Create a list for each binary string, zero padded on left.
    n_bytes   = (n_bits + 7) / 8
    trailbits = n_bits & 7
    trailmask = (~((1 << (8 - trailbits)) - 1)) & 0xff
    zerostr   = binstr_zeropad('', n_bits)
    if astr:
        alist = list((zerostr + astr)[-n_bytes:])
        if trailbits:
            alist[-1] = chr(ord(alist[-1]) & trailmask)
    else:
        alist = list(zerostr)
    if bstr:
        blist = list((zerostr + bstr)[-n_bytes:])
        if trailbits:
            blist[-1] = chr(ord(blist[-1]) & trailmask)
    else:
        blist = list(zerostr)

    index = n_bytes - 1
    vlist = []
    carry = 0

    while index >= 0:
        valbyte, carry = byte_add(alist[index], blist[index], carry)
        vlist.append(valbyte)
        index -= 1
    vlist.reverse()
    return ''.join(vlist)

def calc_hmac(hmac_key, message):
    '''calculate an hmac based on message type'''
    if message.header.msg_type == message.header.NOT_SET:
        raise WesEntropyException("calc_hmac: Cannot calculate hmac for a " +
                                  "message of type \"NOT_SET\".")

    elif message.header.msg_type == message.header.CLIENT_HELLO:
        hmac_data = (str(message.header.msg_number) +
                     str(message.client_hello.client_id) +
                     str(message.client_hello.nonce))

    elif message.header.msg_type == message.header.SERVER_HELLO:
        hmac_data = (str(message.header.msg_number) +
                     str(message.server_hello.page_size) +
                     str(message.server_hello.nonce) +
                     str(message.server_hello.signature))

    elif message.header.msg_type == message.header.DATA_REQUEST:
        hmac_data = (str(message.header.msg_number) +
                     str(message.data_request.num_bytes))

    elif message.header.msg_type == message.header.DATA_DELIVERY:
        hmac_data = (str(message.header.msg_number) +
                     str(message.data_delivery.data))

    elif message.header.msg_type == message.header.STAT_REQUEST:
        hmac_data = str(message.header.msg_number)

    elif message.header.msg_type == message.header.STAT_DELIVERY:
        raise NotImplementedError

    return hmac.new(str(hmac_key), hmac_data)


#pylint: disable=R0921
class WesConfig(object):
    '''Wrapper for config file'''
    def __init__(self, config, default_config_file):
        if config:
            if isinstance(config, ConfigParser.ConfigParser):
                self.config = config
            elif os.path.isfile(config):
                self.config = ConfigParser.ConfigParser()
                self.parse_config(config)
            else:
                raise WesEntropyException('Supplied config does not exist.')
        elif os.path.isfile(default_config_file):
            self.config = ConfigParser.ConfigParser()
            self.parse_config(default_config_file)
        else:
            logging.warning(
                "No config file supplied, using default values.")
            self.config = self.create_default_config()

    @staticmethod
    def create_default_config():
        '''Set default config'''
        raise NotImplementedError('create_default_config')

    def parse_config(self, config_file):
        """Parse config file"""
        try:
            self.config.readfp(open(config_file))
        except IOError as error:
            raise WesEntropyException(
                'Error opening config file %s. (error: %s)' %
                (config_file, error.strerror))

        # If config_file wasn't parsed properly
        if len(self.config.sections()) == 0:
            raise WesEntropyException(
                "Error parsing configuration file, no sections found.")

    def unparse_config(self, config_file):
        '''Unparse config to config_file'''
        with open(config_file) as config_fp:
            self.config.write(config_fp)
#pylint: enable=R0921

#pylint: disable=R0903
class DaemonAction(Enum):
    '''Enum for daemon action'''
    request = 0
    stats = 1
    none = 2
#pylint: enable=R0903

class DaemonMsg(object):
    '''Object for handling Daemon Message'''

    @staticmethod
    def construct_request(num_bytes):
        """Construct request for num_bytes of entropy"""
        assert num_bytes > 0
        return struct.pack('BBBBI',
                           0x01,     # Version
                           DaemonAction.request,
                           0x00,
                           0x00,
                           num_bytes # Number of bytes requested
                          )

    @staticmethod
    def construct_stats_request():
        """Construct stats request"""
        return struct.pack('BBBBI',
                           0x01,   # Version
                           DaemonAction.stats,
                           0x00,
                           0x00,
                           0x00
                          )

    def __init__(self, msg):
        assert len(msg) == 8
        self.num_bytes = 0
        self.action = DaemonAction.none

        try:
            version, action, dummy, dummy, var = struct.unpack('BBBBI', msg)
            if version == 1:
                if action == DaemonAction.request:
                    self.action = DaemonAction.request
                    self.num_bytes = var
                elif action == DaemonAction.stats:
                    self.action = DaemonAction.stats
        except struct.error as error:
            logging.error("Error unpacking request. (error: %s)", error)

    def __repr__(self):
        if self.action == DaemonAction.none:
            return "DaemonMsg(action=DaemonAction.none)"
        elif self.action == DaemonAction.stats:
            return "DaemonMsg(action=DaemonAction.stats)"
        elif self.action == DaemonAction.request:
            return (
                "DaemonMsg(action=DaemonAction.request, num_bytes = %i)" %
                self.num_bytes)
        else:
            assert False

    def is_rand_request(self):
        '''True if this is a request for randomness'''
        return self.action == DaemonAction.request

    def is_stats_request(self):
        '''True if this is a stats request'''
        return self.action == DaemonAction.stats

    def get_num_bytes(self):
        '''Return number of bytes of randomness requested.

        Asserts if this is not a request for randomness'''
        assert self.is_rand_request()
        return self.num_bytes
