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

'''Module for getting stats from WES Entropy Daemon'''
import argparse
import ast
import errno
import logging
import select
import socket
from WesEntropy.Engine.interface import WesClientConfig
from WesEntropy.Engine.utilities import WesConfig, DaemonMsg

class WesEntropyStats(object):
    '''Object for getting stats from WES Entropy Daemon'''

    RECEIVE_SIZE = 4096
    TIMEOUT = 1

    def __init__(self, config):
        if config is None or isinstance(config, str):
            self.config = WesClientConfig(config)
        else:
            assert isinstance(config, WesConfig)
            self.config = config
        self.server_address = self.config.socket_path
        self.socket = None

    def connect(self):
        """Set up socket"""
        try:
            logging.debug("Attempt to connect to daemon: %s",
                          self.server_address)
            self.socket = socket.socket(socket.AF_UNIX,
                                        socket.SOCK_STREAM)
            self.socket.connect(self.server_address)

        except IOError:
            self.destroy()

        if self.socket is None:
            logging.warning("Failed to connect to daemon.")

        return self.socket is not None

    def request_stats(self):
        """Request stats from server."""
        success = False
        if self.socket is None:
            return success

        logging.debug("Request stats")
        request = DaemonMsg.construct_stats_request()

        bytes_written = 0
        try:
            bytes_written = self.socket.send(request)
        except IOError as error:
            logging.error("Error on send (error: %s)",
                          errno.errorcode[error.errno])

        if bytes_written == len(request):
            logging.debug("Requested stats")

            success = True
        else:
            logging.error("Failed to write all bytes: wrote %i",
                          bytes_written)
            self.destroy()
        return success

    def get_waiting_data(self):
        """Get data waiting in socket, after select says it is ready to read"""
        data = ""
        if self.socket is None:
            return data
        try:
            data = self.socket.recv(WesEntropyStats.RECEIVE_SIZE)
            if len(data) > 0:
                logging.debug(
                    "Received stats data")
            else:
                logging.error("Hangup on recv")
                self.destroy()
        except IOError as error:
            logging.error("Error on recv (error: %s)",
                          errno.errorcode[error.errno])
            self.destroy()
        return data

    def get_data(self):
        '''Get data in socket'''
        if self.socket is None:
            return ""

        readable = []
        try:
            readable, _, _ = select.select(
                [self.socket.fileno()], [], [], WesEntropyStats.TIMEOUT)
        except IOError as error:
            logging.error("Error on select (error: %s)",
                          errno.errorcode[error.errno])

        if readable:
            return self.get_waiting_data()

        logging.debug("No waiting data")
        self.destroy()
        return ""

    def destroy(self):
        """Destroy WES Socket"""
        if self.socket is not None:
            try:
                self.socket.close()
            except IOError as error:
                logging.error("Error on socket close (error: %s)",
                              errno.errorcode[error.errno])
            logging.debug("Closed connection to server: %s",
                          self.server_address)
        self.socket = None

    def get_stats(self):
        """Get stats from daemon"""
        self.connect()
        self.request_stats()
        msg = self.get_data()
        stats = None

        if msg != '':
            try:
                stats = ast.literal_eval(msg)
            except ValueError:
                logging.debug('Invalid stats msg: %s', msg)
        self.destroy()
        return stats

def time_string(uptime):
    '''Convert seconds to pretty string'''
    days, remainder = divmod(int(uptime), 24 * 60 * 60)
    hours, remainder = divmod(remainder, 60 * 60)
    minutes, seconds = divmod(remainder, 60)
    return ("%i days, %i hours, %i minutes,  %i seconds" %
            (days, hours, minutes, seconds))

def print_stats(stats_dict):
    '''Pretty print statistics to screen'''
    if stats_dict is None:
        print "No data received from daemon"
        return
    if 'info' in stats_dict:
        print "General Information:"
        if 'version' in stats_dict['info']:
            print "    WES Version:    %s" % stats_dict['info']['version']
        if 'daemon_uptime' in stats_dict['info']:
            print("    Daemon uptime:  %s" %
                  time_string(stats_dict['info']['daemon_uptime']))
            print
        if 'stream' in stats_dict['info']:
            print "    Stream source: %s" % stats_dict['info']['stream']
        if 'drbg' in stats_dict['info']:
            print "    DRBG:          %s" % stats_dict['info']['drbg']
        if 'seed' in stats_dict['info']:
            print "    Seed source:   %s" % stats_dict['info']['seed']
        print
    if 'consumed' in stats_dict:
        print "Randomness consumed:"
        for key, value in stats_dict['consumed'].iteritems():
            print "    %s: %i bytes" % (key, value)
        print
    if 'produced' in stats_dict:
        print "Randomness produced:"
        print "    %i bytes" % stats_dict['produced']

    print ("\nVisit www.whitewoodencryption.com to "
           "harness the power of great entropy.")

def main():
    """Main method"""
    parser = argparse.ArgumentParser(
        description='Get entropy from WES Entropy Daemon')
    parser.add_argument('-d', '--debug', action='store_true',
                        dest='debug', help='Enter debugger')
    parser.add_argument('-c', '--config', dest='config',
                        default=None,
                        help='location of config file, default: ' +
                        '/etc/wesentropy/client.conf')
    parser.add_argument('-v', '--verbose', action='store_true',
                        dest='verbose', help="run with verbose logging")

    args = parser.parse_args()

    if args.debug:
        import ipdb
        ipdb.set_trace()

    if args.verbose:
        logging.basicConfig(format='%(levelname)s: %(message)s',
                            level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(levelname)s: %(message)s')

    stats = WesEntropyStats(args.config)
    stats_dict = stats.get_stats()
    print_stats(stats_dict)

if __name__ == '__main__':
    main()
