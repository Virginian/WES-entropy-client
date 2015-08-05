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

"""WES Entropy Interface"""

import ConfigParser
import datetime
import errno
import logging
import select
import sys
import time
from WesEntropy.Engine.utilities import \
    WesEntropyException, WesConfig, DaemonMsg

# If we are on CentOS, and we are being called from OpenSSL, fake out
# missing _ssl module.  This prevents OpenSSL double initialization.
import platform
if platform.dist()[0] == 'centos' and 'argv' not in dir(sys):
    sys.modules['_ssl'] = None
    import socket
else:
    import socket

DEBUG = True

class WesSocket(object):
    """Socket for WES Entropy Client"""

    select_timeout = 1
    client_timeout = 1
    connect_timeout = 1

    def __repr__(self):
        """Return representation of socket"""

        return (("WesSocket(socket=%s, " +
                 "receive_size=%i, server_address='%s', " +
                 "outstanding_bytes=%i, timer=%s)")
                % (self.socket,
                   self.receive_size,
                   self.server_address,
                   self.outstanding_bytes,
                   self.timer))

    def __init__(self, receive_size, server_addr):
        """Initialize WES Socket"""
        self.server_address = server_addr
        self.receive_size = receive_size

        self.socket = None
        self.outstanding_bytes = 0
        self.timer = None

    def connect(self, blocking):
        """Set up socket"""
        if self.socket is not None:
            self.destroy()

        max_attempts = 2 if blocking else 1

        for attempt in range(max_attempts):
            try:
                logging.debug("Attempt to connect to daemon: %s",
                              self.server_address)
                self.socket = socket.socket(socket.AF_UNIX,
                                            socket.SOCK_STREAM)
                self.socket.connect(self.server_address)
                self.outstanding_bytes = 0
                self.timer = None

            except IOError:
                self.destroy()

            if self.socket is not None:
                break
            if attempt < max_attempts - 1:
                time.sleep(WesSocket.connect_timeout)

            logging.warning("Failed to connect to daemon.")


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
        self.outstanding_bytes = 0
        self.timer = None

    def status_ok(self):
        """Return True if socket is currently OK"""
        return self.socket is not None

    def request_data(self, num_bytes):
        """Request num_bytes of entropy from server

        Return True if request is sent successfully.

        The variable timer is used to track how long it has been since
        the last communication with the server.

        If timer is None, timer is set to the time of the send.
        Otherwise, timer is not changed.
        """
        if num_bytes == 0:
            return True

        success = False

        logging.debug("Request %i bytes", num_bytes)
        if self.status_ok():
            request = DaemonMsg.construct_request(num_bytes)

            bytes_written = 0
            try:
                bytes_written = self.socket.send(request)
            except IOError as error:
                logging.error("Error on send (error: %s)",
                              errno.errorcode[error.errno])

            if bytes_written == len(request):
                logging.debug("Requested %i bytes", num_bytes)
                self.outstanding_bytes += num_bytes
                if self.timer is None:
                    self.timer = datetime.datetime.now()

                success = True
            else:
                logging.error("Failed to write all bytes: wrote %i",
                              bytes_written)
                self.destroy()
        return success

    def get_waiting_data(self):
        """Get data waiting in socket, after select says it is ready to read"""
        data = ""
        try:
            data = self.socket.recv(self.receive_size)
            if len(data) > 0:
                self.outstanding_bytes = max(
                    0, self.outstanding_bytes - len(data))
                if self.outstanding_bytes > 0:
                    self.timer = datetime.datetime.now()

                if self.outstanding_bytes == 0:
                    self.timer = None

                logging.debug(
                    "Received %i bytes random data, outstanding bytes: %i",
                    len(data), self.outstanding_bytes)
            else:
                logging.error("Hangup on recv")
                self.destroy()
        except IOError as error:
            logging.error("Error on recv (error: %s)",
                          errno.errorcode[error.errno])
            self.destroy()
        return data

    def handle_timeouts(self, blocking):
        """Handle timeouts on socket with no data waiting"""
        if blocking:
            logging.warning("No data available on blocking read")
            self.destroy()
        else:
            delta = datetime.datetime.now() - self.timer

            if delta > datetime.timedelta(0, WesSocket.client_timeout):
                logging.error("Server has stopped serving data")
                self.destroy()

    def get_data(self, blocking):
        """Get one socket buffer worth of available data from socket.

        If blocking is True, make the read blocking, with a timeout of 1
        second.

        The variable timer is used to track how long it has been since
        the last communication with the server.

        If data is received from the server, and there are no outstanding
        bytes, timer is set to None.

        If data is received from the server, and there are still outstanding
        bytes, timer is set to current time.

        If no data is received from server, and it has been more than 1 second
        since the most recent data from the server, then the server is
        presumed to have gone down, and the connection is destroyed.
        """
        if not self.status_ok():
            return ""

        timeout = WesSocket.select_timeout if blocking else 0

        readable = []
        try:
            readable, _, _ = select.select(
                [self.socket.fileno()], [], [], timeout)
        except IOError as error:
            logging.error("Error on select (error: %s)",
                          errno.errorcode[error.errno])
            self.destroy()
            return ""

        if readable:
            return self.get_waiting_data()
        else:
            self.handle_timeouts(blocking)
            return ""

class WesBuffer(object):
    """Buffer for WES Entropy Client"""

    def __init__(self, buffer_size):
        """Initialize WES Buffer"""
        self.buff_size = buffer_size
        self.buff = bytearray(self.buff_size)
        self.read_index = 0
        self.write_index = 0
        self.logged_zero = False

    def __repr__(self):
        """Return representation of WesBuffer"""
        if len(self.buff) > 80:
            output_buffer = str(self.buff[0:80]) + "..."
        else:
            output_buffer = str(self.buff)
        return (("WesBuffer(buffer='%s', buffer_size=%s, " +
                 "read_index=%i, write_index=%i)")
                % (output_buffer,
                   self.buff_size,
                   self.read_index,
                   self.write_index))

    def bytes_ready(self):
        """Number of bytes available for reading"""
        return (self.write_index - self.read_index) % self.buff_size

    def bytes_needed(self):
        """Number of bytes that are needed to refill buffer"""
        return self.buff_size - 1 - self.bytes_ready()

    def empty(self):
        """True if the buffer is empty"""
        return self.write_index == self.read_index

    def full(self):
        """True if the buffer is full of available data"""
        return (self.write_index + 1) % self.buff_size == self.read_index

    def add_random_data(self, data):
        """Add data into buffer.

        Do not over-write data already available.
        """
        bytes_to_copy = min(self.bytes_needed(), len(data))

        for item in data[:bytes_to_copy]:
            self.buff[self.write_index] = item
            self.write_index += 1
            if self.write_index == self.buff_size:
                self.write_index = 0

    def get_random_data(self, num_bytes):
        """Return num_bytes of available random data.

        If there is not enough, return what is available
        """
        if self.bytes_ready() > 0 or not self.logged_zero:
            logging.debug("Entropy pool has %i bytes, getting %i bytes",
                          self.bytes_ready(), num_bytes)
            # Prevent log spam
            if self.bytes_ready() == 0:
                self.logged_zero = True
            else:
                self.logged_zero = False

        if num_bytes > self.bytes_ready():
            num_bytes = self.bytes_ready()

        if self.read_index + num_bytes < self.buff_size:
            end_index = self.read_index + num_bytes
            data = self.buff[self.read_index:end_index]
        else:
            end_index = self.read_index + num_bytes - self.buff_size
            data = (self.buff[self.read_index:self.buff_size] +
                    self.buff[0:end_index])
        self.read_index = end_index

        return data

class WesClientConfig(WesConfig):
    '''Wrapper for client configuration'''
    default_config_file = '/etc/wesentropy/client.conf'

    def __init__(self, config):
        WesConfig.__init__(self, config, WesClientConfig.default_config_file)
        self.socket_path = self.config.get('daemon', 'socket_path')


    @staticmethod
    def create_default_config():
        '''Return a config file for client.'''
        config = ConfigParser.ConfigParser()
        config.add_section('daemon')

        config.set('daemon', 'socket_path', '/var/run/wesentropy/wes.socket')

        return config

    @staticmethod
    def get_default_socket():
        '''Get default socket path'''
        return '/var/run/wesentropy/wes.socket'


class WesEntropyClient(object):
    """WES Entropy Client"""

    if DEBUG:
        INTERNAL_BUFFER_SIZE = 512
        RECEIVE_BUFFER_SIZE = 256
    else:
        INTERNAL_BUFFER_SIZE = 8193
        RECEIVE_BUFFER_SIZE = 4096

    def __init__(self, config=None, receive_size=None,
                 buffer_size=None):
        """Initialize WES Entropy Client"""
        self.config = WesClientConfig(config)

        if buffer_size is None:
            buffer_size = WesEntropyClient.INTERNAL_BUFFER_SIZE
        else:
            logging.warning("Overriding default buffer size with %i",
                            buffer_size)

        if receive_size is None:
            receive_size = WesEntropyClient.RECEIVE_BUFFER_SIZE
        else:
            logging.warning("Overriding default receive size with %i",
                            receive_size)

        self.buff = WesBuffer(buffer_size)
        self.socket = WesSocket(receive_size, self.config.socket_path)

        self.request_size = buffer_size / 8
        self.counter = 0

        self.socket.connect(True)
        self.socket.request_data(self.buff.bytes_needed())


    def __repr__(self):
        """Return representation of WesClient"""
        return (("WesEntropyClient(socket=%s, buffer=%s, " +
                 "request_size=%i, counter=%i)")
                % (self.socket,
                   self.buff,
                   self.request_size,
                   self.counter))

    def destroy(self):
        """Destroy resources for WES Entropy Client"""
        self.socket.destroy()


    def retrieve_waiting_data(self):
        """Put any data waiting in the socket recv buffer into the WES Buffer.
        """
        while True:
            if (self.socket.outstanding_bytes == 0 or
                    self.buff.bytes_needed() == 0):
                break

            data = self.socket.get_data(self.buff.empty())

            if len(data) != 0:
                self.buff.add_random_data(data)
            else:
                break

    def copy_available_data(self, data, index):
        """Put available random data into bytearray data.

        index is the location of the first byte to be written.
        Only fills data until
          * data is full, or
          * self.counter == self.request_size, or
          * random buffer is empty.

        Returns new index.
        """
        bytes_to_get = min(self.request_size - self.counter,
                           len(data) - index,
                           self.buff.bytes_ready())
        new_data = self.buff.get_random_data(bytes_to_get)
        for (value, i) in zip(new_data, range(index, index + len(new_data))):
            data[i] = value

        self.counter += len(new_data)
        index += len(new_data)
        if bytes_to_get != 0:
            logging.debug("Copied %i bytes of data into user bytearray",
                          bytes_to_get)

        return index

    def make_new_request(self):
        """Request new data if appropriate.

        This includes re-establishing the connection if it has failed
        """
        if self.counter == self.request_size:
            self.counter = 0
            self.socket.request_data(self.request_size)

        if not self.socket.status_ok():

            self.socket.connect(self.buff.empty())
            self.socket.request_data(self.buff.bytes_needed())

            if self.buff.empty():
                self.retrieve_waiting_data()
                if self.buff.empty():
                    logging.critical("No random data available")
                    raise WesEntropyException("No random data available")

    def get_bytes(self, num_bytes):
        """Return num_bytes of random data.

        If an error occurs, return the empty string.
        """
        logging.info("User has requested %i bytes", num_bytes)

        index = 0
        data = bytearray(num_bytes)

        try:
            while num_bytes - index > 0:
                self.retrieve_waiting_data()
                index = self.copy_available_data(data, index)
                self.make_new_request()
        except WesEntropyException:
            return ""
        return str(data)
