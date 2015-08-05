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

"""WES Entropy Client"""

import argparse
import sys
import time
from WesEntropy.Engine.interface import WesEntropyClient

class WesClientSingleton(object):
    """Singleton for WES Entropy Client"""
    singleton = None

    WES_ENGINE_ERROR_NONE = 0
    ERROR_FILE_NOT_FOUND = 1
    ERROR_READ_ERROR = 2
    ERROR_INVALID_CONTEXT = 3

    @classmethod
    def initialize(cls, config):
        """Initialize WES Entropy Client Singleton.

        Return WES_ENGINE_ERROR_NONE if connection can be
        established with server.
        """
        if cls.singleton is None:
            cls.singleton = WesEntropyClient(config)
            if cls.singleton.socket.status_ok():
                return cls.WES_ENGINE_ERROR_NONE
            else:
                cls.destroy()
                return cls.ERROR_READ_ERROR

    @classmethod
    def get_bytes(cls, num_bytes):
        """Get num_bytes data from WES Entropy Client Singleton.

        Return the empty string if error occurs.
        """
        return cls.singleton.get_bytes(num_bytes)

    @classmethod
    def destroy(cls):
        """Destroy WES Entropy Client Singleton"""
        if cls.singleton is not None:
            cls.singleton.destroy()
        cls.singleton = None


def initialize(config=None, verbose=True):
    """Initialize WES Client Singleton.

    Return WES_ENGINE_ERROR_NONE if connection can be established with server.
    """
    if verbose:
        print "ewes: init"
    return WesClientSingleton.initialize(config)


def get_bytes(num_bytes):
    """Fill data bytearray with random data from WES Client Singleton.

    Return the number of bytes written.
    """
    data = WesClientSingleton.get_bytes(num_bytes)
    return data


MAX_REQUEST = 10000

def output_bytes_and_check(num_bytes, binary):
    '''Get num_bytes and check that correct number bytes returned.

    If correct number, output to stdout in hex or binary.
    If not, raise RuntimeError.'''
    data = WesClientSingleton.get_bytes(num_bytes)
    if len(data) != num_bytes:
        raise RuntimeError(
            "Requested %i bytes from daemon, received %i bytes" %
            (num_bytes, len(data)))
    sys.stdout.write(data if binary else data.encode('hex'))

def output_bytes(num_bytes, binary):
    '''Get num_bytes from WES Client Singleton and output to stdout

    If request is large, break into multiple requests'''
    for _ in range(num_bytes / MAX_REQUEST):
        output_bytes_and_check(MAX_REQUEST, binary)

    final_bytes = num_bytes % MAX_REQUEST
    output_bytes_and_check(final_bytes, binary)

def interactive_loop():
    '''Run interactive loop.

    User inputs number of bytes, client gets them.'''
    instructions = "Enter a number of random bytes to get, or 'q' to quit."

    sys.stdout.write(instructions)
    while True:
        user_in = raw_input('\n\nrandom:$ ')
        if user_in in ['q', 'quit', 'exit']:
            return
        else:
            try:
                val = int(user_in)
                sys.stdout.write('DATA: ')
                output_bytes(val, binary=False)
            except ValueError:
                sys.stdout.write(instructions)

def non_interactive_loop(number, seconds):
    """Run a non-interactive loop"""
    if not number or not seconds:
        raise RuntimeError('Running with -l|--loop requires the use of ' +
                           '-n|--number and -s|--seconds.')

    while True:
        sys.stdout.write('DATA: ')
        output_bytes(number, binary=False)
        sys.stdout.write('\n\n')
        time.sleep(seconds)

def destroy(verbose=True):
    """Destroy WES Client Singleton"""
    if verbose:
        print "ewes: destroy"
    WesClientSingleton.destroy()


def main():
    """Main method"""
    parser = argparse.ArgumentParser(
        description='Get entropy from WES Entropy Daemon')
    parser.add_argument('-d', '--debug', action='store_true',
                        dest='debug', help='Enter debugger')
    parser.add_argument('-l', '--loop', action='store_true',
                        dest='loop', help='Request n bits every s seconds.' +
                        ' Used with -n|--number and -s|--seconds')
    parser.add_argument('-c', '--config', dest='config',
                        default=None,
                        help='location of config file, default: ' +
                        '/etc/wesentropy/client.conf')
    parser.add_argument('-n', '--number', type=int,
                        help='Number of random bytes to produce')
    parser.add_argument('-s', '--seconds', type=float,
                        help='Interval to produce random bytes. '+
                        'Used with -l|--loop.')
    parser.add_argument('-b', '--binary', action='store_true',
                        help='Print random bytes in raw binary ' +
                        '(used with -n|--number argument')

    args = parser.parse_args()

    if args.debug:
        import ipdb
        ipdb.set_trace()

    print_wes = not args.binary and not args.number

    try:
        if (initialize(args.config, print_wes) ==
                WesClientSingleton.WES_ENGINE_ERROR_NONE):
            if args.loop:
                non_interactive_loop(args.number, args.seconds)
            elif args.number:
                output_bytes(args.number, args.binary)
                if not args.binary:
                    sys.stdout.write('\n')
            else:
                interactive_loop()

            destroy(print_wes)
        else:
            print "Cannot initialize Wes Client"
            sys.exit(1)
    except RuntimeError as error:
        print error
        sys.exit(1)


if __name__ == '__main__':
    main()
