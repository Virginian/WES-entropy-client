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

"""WES Entropy Daemon"""

import argparse
import ast
import ConfigParser
import os
import logging
import select
import socket
import errno
import time
import daemon
import signal
import lockfile
import traceback
from WesEntropy.Engine.engine import EntropyEngine
from WesEntropy.Engine.utilities import \
  WesEntropyException, WesConfig, DaemonMsg

DEBUG = True

#pylint: disable=R0902
class WesDaemonConfig(WesConfig):
    '''Wrapper for daemon config file'''

    def __init__(self, config, server):
        if server:
            self.default_config_file = '/etc/wesentropy/server.conf'
        else:
            self.default_config_file = '/etc/wesentropy/client.conf'

        WesConfig.__init__(self, config, self.default_config_file)

        self.working_dir = self.config.get('DEFAULT', 'working_dir')

        self.socket_path = self.config.get('daemon', 'socket_path')

        self.seed_source = ast.literal_eval(
            self.config.get('seed_source',
                            self.config.options('seed_source')[0]))

        self.stream_source = ast.literal_eval(
            self.config.get('stream_source',
                            self.config.options('stream_source')[0]))

        self.drbg_spec = self.config.get('drbg', 'drbg_spec')
        self.reseed_rate = self.config.get('drbg', 'reseed_rate')

    @staticmethod
    def create_default_config():
        """Create default configuration"""
        config_parser = ConfigParser.ConfigParser()
        config_parser.add_section('daemon')
        config_parser.add_section('seed_source')
        config_parser.add_section('stream_source')
        config_parser.add_section('drbg')

        config_parser.set('DEFAULT', 'working_dir', '/var/run/wesentropy')

        config_parser.set('daemon', 'socket_path',
                          '%(working_dir)s/wes.socket')

        config_parser.set('seed_source', 'seed_source1', '"FILE_dev_urandom"')

        config_parser.set(
            'stream_source', 'stream_source1', '"FILE_dev_urandom"')

        config_parser.set('drbg', 'drbg_spec', 'CTR_DRBG_AES_256')
        config_parser.set('drbg', 'reseed_rate', 'LINESPEED')
        return config_parser

    @classmethod
    def create_network_config(cls):
        '''Create default configuration for getting entropy over network'''
        config_parser = cls.create_default_config()
        config_parser.set(
            'DEFAULT', 'working_dir', '/var/run/wesentropy')

        config_parser.set('seed_source', 'seed_source1', '"FILE_dev_urandom"')

        #pylint: disable=C0301
        config_parser.set('stream_source', 'stream_source1',
                          '"ENTROPY SERVER", "ws://localhost:8000", '
                          '"NirKYaqw3dQcxJzcq", "gH5Ha/fLR1nHJqnuvVUw+fupJ9UZTP2IUu2d/nPdbVp3VTMHZNFGJfFkRE4B9+7M"')
        #pylint: enable=C0301

        return config_parser

    @classmethod
    def create_server_config(cls):
        '''Create default configuration for daemon attached to WES Server'''
        config_parser = cls.create_default_config()
        config_parser.set(
            'DEFAULT', 'working_dir', '/var/run/wesentropy_server')

        config_parser.set('seed_source', 'seed_source1', '"FILE_dev_urandom"')

        config_parser.set(
            'stream_source', 'stream_source1', '"FILE_dev_urandom"')

        return config_parser

    @classmethod
    def set_seed_source(cls, config_parser, value):
        '''Set seed source for config file'''
        config_parser.set('seed_source', 'seed_source1', value)

    @classmethod
    def set_stream_source(cls, config_parser, value):
        '''Set stream source for config file'''
        config_parser.set('stream_source', 'stream_source1', value)

    def parse_config(self, config_file):
        """parse config file and do basic sanity tests"""
        WesConfig.parse_config(self, config_file)

        # Sanity check config file
        # Check that all sections exist
        missing = {'daemon', 'seed_source', 'stream_source', 'drbg'} - \
                  set(self.config.sections())

        if len(missing) > 0:
            raise WesEntropyException(
                "Error parsing config file, missing required section(s) %s." %
                ", ".join(str(tmp) for tmp in missing))

        # Check that [daemon] contains required information
        missing = {'socket_path'} - \
                  set(self.config.options('daemon'))

        if len(missing) > 0:
            raise WesEntropyException(
                "Error parsing config file, missing required value(s) "
                "%s, in [conneciton]." %
                ", ".join(str(tmp) for tmp in missing))

        # Check that [stream_source] has at least one value, and that it's valid
        if len(self.config.options('stream_source')) < 1:
            raise WesEntropyException(
                "Error parsing config file, [stream_source] must have at "
                "least one option configured.")

        # Check that [seed_source] has at least one value, and that it's valid
        if len(self.config.options('seed_source')) < 1:
            raise WesEntropyException(
                "Error parsing config file, [seed_source] must have at "
                "least one option configured.")
#pylint: enable=R0902


#pylint: disable=R0902
class WesEntropyDaemon(object):
    """WES Entropy Daemon"""

    if DEBUG:
        PAGE_SIZE = 64
        READ_SIZE = 8
    else:
        PAGE_SIZE = 1024
        READ_SIZE = 96

    def __init__(self, config=None, server=False):
        self.config = WesDaemonConfig(config, server)

        logging.debug("Creating Entropy Engine")

        self.engine = EntropyEngine(
            self.config.drbg_spec, self.config.seed_source,
            self.config.reseed_rate, self.config.stream_source)

        self.connections = {}
        self.requests = {}
        self.serversocket = None
        self.epoll = None
        self.running = True
        self.active_timeout = {}
        self.start_time = time.time()

        self.drbg_fail_count = 0

    def create_server_socket(self):
        """Create a server socket and epoll for daemon"""
        # import ipdb; ipdb.set_trace()
        socket_dir = os.path.dirname(self.config.socket_path)
        if not os.path.exists(socket_dir):
            raise WesEntropyException(
                "Socket directory \'%s\' does not exist.\n" % socket_dir +
                "Please create it by running the following command:\n" +
                "sudo mkdir %s && sudo chmod 777 %s" % (socket_dir, socket_dir))
        try:
            os.unlink(self.config.socket_path)
        except OSError:
            if os.path.exists(self.config.socket_path):
                raise WesEntropyException("Socket path already exists (%s)." %
                                          self.config.socket_path)

        try:
            self.serversocket = socket.socket(socket.AF_UNIX,
                                              socket.SOCK_STREAM)
            self.serversocket.setsockopt(socket.SOL_SOCKET,
                                         socket.SO_REUSEADDR, 1)

            self.serversocket.bind(self.config.socket_path)
            self.serversocket.listen(1)
            self.serversocket.setblocking(0)
            os.chmod(self.config.socket_path, 0766)
            logging.debug(
                "Daemon listening on '%s'", self.config.socket_path)
        except IOError as error:
            if error.errno == errno.EADDRINUSE:
                raise WesEntropyException(
                    "Address already in use. (error: %s)" %
                    errno.errorcode[error.errno])
            else:
                raise WesEntropyException(
                    "Error setting up socket server (%s). (error: %s)" %
                    (self.config.socket_path, errno.errorcode[error.errno]))

        try:
            self.epoll = select.epoll()
            self.epoll.register(self.serversocket.fileno(), select.EPOLLIN)
            logging.debug("Registered server socket with epoll.")
        except IOError as error:
            raise WesEntropyException(
                "Serversocket already registered with epoll. (error: %s)" %
                errno.errorcode[error.errno])

    def get_events(self, pending_requests):
        """Get any pending socket events"""
        if pending_requests:
            poll_timeout = 0.0
        else:
            poll_timeout = 0.1

        try:
            events = self.epoll.poll(poll_timeout)
            #logging.debug("S: Polled with timeout %s, got %s events.",
            #              poll_timeout,
            #              len(events))
        except select.error as error:
            if error.errno == errno.EINTR:
                logging.warning(
                    "Epoll was interupted by signal. (error: %s).",
                    errno.errorcode[error.errno])
            else:
                raise WesEntropyException(
                    "Error calling epoll. (error: %s)." %
                    errno.errorcode[error.errno])

        return events

    def setup_new_client(self):
        """Establish a new client connection"""
        # pylint: disable=E1101
        add_client = True

        try:
            connection, dummy_address = self.serversocket.accept()
            logging.debug(
                "Accepted client with fd: %s", connection.fileno())

            connection.setblocking(0)
        except IOError as error:
            logging.error("Error accepting client connection. (error: %s)",
                          errno.errorcode[error.errno])
            add_client = False

        try:
            self.epoll.register(connection.fileno(), select.EPOLLIN)
        except select.error as error:
            if (error.errno == errno.ENOSPC or
                    error.errno == errno.ENOMEM):
                logging.warning(
                    "Cannot add more clients to epoll instance, "
                    "dropping client. (error: %s)",
                    errno.errorcode[error.errno])
                connection.shutdown()
                connection.close()
                add_client = False
            elif error.errno == errno.EEXIST:
                logging.warning(
                    "Client already registered to epoll. (error: %s)",
                    errno.errorcode[error.errno])
            else:
                raise WesEntropyException("Error in epoll. (error: %s)" %
                                          errno.errorcode[error.errno])

        # If there wasn't an error, add client to connections
        if add_client:
            self.connections[connection.fileno()] = connection
            logging.debug("Set up new client: %i", connection.fileno())
            self.requests[connection.fileno()] = {'bytes_req'   : 0,
                                                  'partial_req' : "",
                                                  'send_stats'  : False}
        # pylint: enable=E1101

    def reset_drbg(self):
        """get new instance of drbg if errors occurs in current instance"""
        self.engine = EntropyEngine(
            self.config.drbg_spec, self.config.seed_source,
            self.config.reseed_rate, self.config.stream_source)

    def handle_error(self, fileno):
        """Cleanup after client connection error"""
        # Clean up send timeout
        if fileno in self.active_timeout:
            del self.active_timeout[fileno]

        try:
            logging.debug("Unregistering %s from epoll.", fileno)
            self.epoll.unregister(fileno)
        except select.error as error:
            if error.errno == errno.ENOENT:
                logging.error(
                    "Error unregistering %s from epoll. (error: %s)",
                    fileno, errno.errorcode[error.errno])
            else:
                raise WesEntropyException(
                    "Error unregistering client from epoll. (error: %s)" %
                    errno.errorcode[error.errno])
        try:
            self.connections[fileno].close()
        except IOError as error:
            logging.error("Error on socket close. (error: %s)",
                          errno.errorcode[error.errno])

        logging.debug("Closed connection to %i.", fileno)
        if fileno in self.connections:
            del self.connections[fileno]
        if fileno in self.requests:
            del self.requests[fileno]

    def read_request(self, fileno):
        """Store information about the data request for processing"""
        try:
            new_request = self.connections[fileno].recv(
                WesEntropyDaemon.READ_SIZE)
            request = self.requests[fileno]['partial_req'] + new_request
        except IOError as error:
            if error.errno == errno.EAGAIN or error.errno == errno.EWOULDBLOCK:
                logging.warning("No data for recv to get. (error: %s)",
                                errno.errorcode[error.errno])
            else:
                logging.error("Error on recv (error: %s)",
                              errno.errorcode[error.errno])
                logging.debug("Calling handle_error on %s.", fileno)
                self.handle_error(fileno)

        num_requests = len(request) / 8

        logging.debug("Current num_requests: %i", num_requests)

        for index in range(num_requests):
            msg = DaemonMsg(request[8*index:8*index+8])
            if msg.is_rand_request():
                self.requests[fileno]['bytes_req'] += msg.get_num_bytes()
            elif msg.is_stats_request():
                self.requests[fileno]['send_stats'] = True
            else:
                continue

        self.requests[fileno]['partial_req'] = request[num_requests*8:]

    def get_random_data(self):
        """Get random data"""
        rtn = ""
        num_errors = 0
        while len(rtn) < WesEntropyDaemon.PAGE_SIZE:
            # Request to Generate is in bits
            retcode, data = self.engine.generate(WesEntropyDaemon.PAGE_SIZE * 8)
            if retcode == 'ERROR':
                logging.debug("Ran generate, got: %s - %s", retcode, data)
            else:
                logging.debug("Ran generate, got: %s", retcode)
            if retcode == 'SUCCESS':
                rtn += data
                num_errors = 0
            elif retcode == 'DRBG_ONLY':
                logging.warning(
                    "Error with stream source, using DRBG only.")
                rtn += data
                num_errors = 0
            else:
                num_errors += 1
                time.sleep(0.1)
                if num_errors == 10:
                    logging.warning("DRBG Error: %s: %s", retcode, data)
                    return None

        return rtn[:WesEntropyDaemon.PAGE_SIZE]

    #pylint: disable=R0912
    def serve_requests(self):
        """Serve one buffer to each client that requests data.

        Return True if there are pending requests upon return.
        """
        pending_requests = False

        #logging.debug("Clients waiting: %s", str(self.connections.keys()))
        for fileno in self.connections.keys():
            if self.requests[fileno]['send_stats']:
                try:
                    stats = self.engine.get_stats()
                    stats['info']['daemon_uptime'] = (
                        time.time() - self.start_time)
                    self.connections[fileno].send(repr(stats))
                except IOError as error:
                    pass
                self.handle_error(fileno)
                continue

            if self.requests[fileno]['bytes_req'] > 0:
                try:
                    random_data = self.get_random_data()

                    if random_data:
                        byteswritten = self.connections[fileno].send(
                            random_data)

                        self.requests[fileno]['bytes_req'] -= byteswritten
                        if self.requests[fileno]['bytes_req'] < 0:
                            self.requests[fileno]['bytes_req'] = 0

                        logging.debug(
                            "Sent %i bytes to client, outstanding bytes: %i",
                            byteswritten,
                            self.requests[fileno]['bytes_req'])

                        # Mark that fileno doesn't have timeout
                        if fileno in self.active_timeout:
                            del self.active_timeout[fileno]
                        self.drbg_fail_count = 0
                    else:
                        logging.warning("Error getting data from DRBG.")
                        self.drbg_fail_count += 1
                        if self.drbg_fail_count < 5:
                            logging.warning("Resetting DRBG.")
                            self.reset_drbg()
                        else:
                            raise WesEntropyException("DRBG fatal error.")

                except IOError as error:
                    if (error.errno == errno.EAGAIN or
                            error.errno == errno.EWOULDBLOCK):
                        # No data sent, 1 min timeout
                        if self.send_timeout(fileno):
                            logging.error(
                                "Client %i hasn't accepted data "
                                "for 1 minute, closing connection.",
                                fileno)
                            self.handle_error(fileno)
                    else:
                        logging.debug(
                            "Error sending data to client %i, "
                            "closing connection. (error: %s)",
                            fileno, errno.errorcode[error.errno])
                        self.handle_error(fileno)

                if fileno in self.requests:
                    if self.requests[fileno]['bytes_req'] > 0:
                        pending_requests = True
                    else:
                        self.requests[fileno]['bytes_req'] = 0

        return pending_requests
    #pylint: enable=R0912

    def send_timeout(self, fileno):
        """Timeout for socket sends that return EWOULDBLOCK or EAGAIN"""
        # New timeout for fileno? Add "fileno : curr_time" to dict
        if fileno not in self.active_timeout:
            self.active_timeout[fileno] = time.time()

        # If 1 min has passed since timeout start return true
        if time.time() >= self.active_timeout[fileno] + 60:
            logging.debug("Timeout for %s is at %s sec.",
                          fileno, time.time() - self.active_timeout[fileno])
            return True
        else:
            logging.debug("Timeout for %s has expired.",
                          fileno)
            return False

    #pylint: disable=W0613
    @classmethod
    def sig_handler(cls, sig_num, stack_frame):
        """Wrapper function for cleanup to pass as the signal handler."""
        cls.cleanup()
    #pylint: enable=W0613

    @classmethod
    def cleanup(cls):
        """Clean up and close server socket"""
        if cls.wes_daemon is not None:
            # fails if called multiple times - should we put a check?
            if cls.wes_daemon.epoll is not None:
                try:
                    cls.wes_daemon.epoll.unregister(
                        cls.wes_daemon.serversocket.fileno())
                    cls.wes_daemon.epoll.close()
                    logging.debug("Cleaned up epoll.")
                except select.error as error:
                    logging.warning(
                        "Failed to cleanup epoll. (error: %s)",
                        errno.errorcode[error.errno])

            if cls.wes_daemon.serversocket is not None:
                try:
                    cls.wes_daemon.serversocket.close()
                    logging.debug("Cleaned up server socket.")
                except IOError as error:
                    logging.warning(
                        "Failed to cleanup server socket. (error: %s)",
                        errno.errorcode[error.errno])
        cls.wes_daemon = None

    def process_events(self, pending_requests):
        """Process events returned from epoll"""
        events = self.get_events(pending_requests)

        #logging.debug("Events: ", str(events))

        for fileno, event in events:
            if fileno == self.serversocket.fileno():
                self.setup_new_client()

            elif event & (select.EPOLLERR | select.EPOLLHUP):
                if event & select.EPOLLERR:
                    logging.debug(
                        "Encountered epoll error with client %s.",
                        fileno)
                else:
                    logging.debug("Client %s disconnected.", fileno)
                self.handle_error(fileno)

            elif event & select.EPOLLIN:
                self.read_request(fileno)

    def main_loop(self):
        """main loop for running wesentropyd"""
        # pylint: disable=W0703
        try:
            self.create_server_socket()

            pending_requests = False
            while self.running:
                self.process_events(pending_requests)
                pending_requests = self.serve_requests()
        except Exception as error:
            if isinstance(error, WesEntropyException):
                logging.error(error.message)
            else:
                logging.error("%s", traceback.format_exc())
                logging.error("Unknown error. (error %s)",
                              error.message)
        finally:
            self.engine.cleanup()
            self.cleanup()
        # pylint: enable=W0703

    def testing_get_partial_req(self, fileno):
        """Test function"""
        return self.requests[fileno]

    def __repr__(self):
        return ('WesEntropyDaemon(server_address=%s, '
                'connections=%s, requests=%s)' %
                (self.config.socket_path, self.connections, self.requests))

    wes_daemon = None

    @classmethod
    def start_daemon(cls, config, server, verbose, asdaemon):
        '''Start WES Entropy Daemon'''
            #TODO: change to /var/log/wes_entropy/wes_entropy.log

        log_format = '%(levelname)s: %(threadName)s %(message)s'
        if asdaemon:
            d_config = WesDaemonConfig(config, server)
            lock_file = os.path.join(d_config.working_dir, 'wesentropy.pid')

            if not os.path.exists(d_config.working_dir):
                os.makedirs(d_config.working_dir)


            daemon_context = daemon.DaemonContext(
                working_directory=d_config.working_dir,
                umask=0o001,
                pidfile=lockfile.FileLock(lock_file))

            daemon_context.signal_map = {
                signal.SIGTERM: cls.sig_handler,
                signal.SIGHUP: cls.sig_handler}

            with daemon_context:
                if verbose:
                    logging.basicConfig(format=log_format,
                                        filename='wes_entropy.log',
                                        level=logging.DEBUG)
                else:
                    logging.basicConfig(format=log_format,
                                        filename='wes_entropy.log')

                cls.wes_daemon = WesEntropyDaemon(
                    config=config, server=server)
                cls.wes_daemon.main_loop()
        else:
            if verbose:
                logging.basicConfig(format=log_format,
                                    level=logging.DEBUG)
            else:
                logging.basicConfig(format=log_format)

            cls.wes_daemon = WesEntropyDaemon(
                config=config, server=server)
            cls.wes_daemon.main_loop()


def main():
    """Main method"""
    parser = argparse.ArgumentParser(description='Provide entropy to clients')
    parser.add_argument('-c', '--config', default=None,
                        dest='config',
                        help=("path to config file, "
                              "default for server daemon: "
                              "/etc/wesentropy/server.conf, "
                              "default for client daemon: "
                              "/etc/wesentropy/client.conf"))
    parser.add_argument('-d', '--debug', action='store_true',
                        dest='debug', help='enter debugger')
    parser.add_argument('-v', '--verbose', action='store_true',
                        dest='verbose', help="run with verbose logging")
    parser.add_argument('-n', '--nodaemon', action='store_true',
                        dest='no_daemon', help='run in forground')
    parser.add_argument('-s', '--server', action='store_true',
                        dest='server', help='use for wesentropy_server')
    args = parser.parse_args()

    if args.debug:
        import ipdb
        ipdb.set_trace()

    if args.config is not None:
        args.config = os.path.realpath(args.config)

    WesEntropyDaemon.start_daemon(args.config, args.server,
                                  args.verbose, not args.no_daemon)


if __name__ == '__main__':
    main()
