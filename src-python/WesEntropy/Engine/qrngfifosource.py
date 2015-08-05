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

'''WES QRNG Source'''

import os
import logging
import time
import threading
from enum import Enum
from subprocess import Popen
import WesEntropy.Engine.utilities as utilities
from WesEntropy.Engine.interface import WesBuffer
import WesEntropy.Engine.entropysource as entropysource

#pylint: disable=R0903
class ClientState(Enum):
    '''Enum for client state'''
    pre_init = 0
    init = 1
    expect_hello = 2
    expect_data = 3
#pylint: enable=R0903

#pylint: disable=R0902
class QRNGSource(entropysource.EntropySource):
    '''Entropy source based on QRNG Fifo workaround.'''

    BUFFER_SIZE = 8193
    READ_SIZE  = 64

    def __init__(self, fifo_number):
        entropysource.EntropySource.__init__(self)
        self.buff = WesBuffer(QRNGSource.BUFFER_SIZE)

        self.fifo_number = fifo_number

        self.thread_spawned = None
        self.thread = None
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.init_event = threading.Event()

        self.start_fifo_client()

    def start_fifo_client(self):
        '''Start the fifo client'''
        logging.debug("Thread spawned: %s", self.thread_spawned)
        if not self.thread_spawned:
            self.thread_spawned = True
            self.init_event.clear()
            self.stop_event.clear()
            self.thread = threading.Thread(target=self._start_fifo)
            self.thread.start()

    def get_entropy_input(self, security_strength,
                          min_bits, max_bits,
                          prediction_resistance):
        '''Return entropy from network source.'''

        if max_bits < min_bits:
            raise ValueError('max_length must be greater than or ' +
                             'equal to min_length')

        min_bytes = (min_bits + 7) / 8

        random_bytes = ''
        backoff = 0.01

        if not self.init_event.is_set():
            while not self.init_event.is_set():
                time.sleep(.1)

            # TODO: Make less hacky (still timing based)
            time.sleep(1)

        # Only try to get data when buffer isn't empty to prevent
        #  a two second decay when qrng goes down and drbg is running
        #  off old seed (qrng as seed case).
        if self.buff.bytes_ready() > 0:
            while len(random_bytes) < min_bytes:
                with self.lock:
                    new_bytes = self.buff.get_random_data(
                        min_bytes)

                if len(new_bytes) == 0:
                    logging.debug("Sleep %f", backoff)
                    if backoff > 2.0:
                        break
                    time.sleep(backoff)
                    backoff = backoff * 2
                else:
                    backoff = 0.01
                    random_bytes += str(new_bytes)

            self.total_bytes += len(random_bytes)

            random_bytes = utilities.binstr_leftmost(random_bytes, max_bits)

        if len(random_bytes) >= min_bytes:
            return 'SUCCESS', random_bytes
        else:
            self.restart_fifo_client()
            return 'ERROR', (("Internal pool doesn't contain "
                              "enough entropy. Only got %i bytes.") %
                             len(random_bytes))

    def restart_fifo_client(self):
        '''Close qrng fifo source.'''
        logging.debug("Stopping qrng fifo client")
        if self.stop_event:
            self.stop_event.set()

        # Wait for the thread to exit before spawning it again
        while self.stop_event.is_set():
            time.sleep(.1)

        self.thread_spawned = False

        self.start_fifo_client()

    def _start_fifo(self):
        '''Start fifo client'''
        logging.debug("Starting qrng fifo client.")
        #pylint: disable=E1121
        self.FifoClient(self.fifo_number, self.buff, self.lock,
                        self.stop_event, self.init_event)
        #pylint: enable=E1121
        logging.debug("QRNG Fifo client closed.")

    def close_entropy_source(self):
        '''Close entropy source'''
        if self.stop_event:
            self.stop_event.set()

        self.thread_spawned = False

    def get_name(self):
        '''Get name'''
        return '/tmp/wesqrng' + str(self.fifo_number)


    #pylint: disable=E1101,R0913
    class FifoClient(object):
        '''QRNG Fifo client'''

        def __init__(self, fifo_number, buff,
                     lock, stop_event, init_event):
            self.fifo_path = '/tmp/wesqrng' + str(fifo_number)
            self.fifo_number = fifo_number
            self.stop_event = stop_event
            self.init_event = init_event
            self.lock = lock
            self.buff = buff
            self.bytes_req = 0

            self.c_client = None

            self.spawn_c_client()
            self.run()
            self.c_client.kill()
            self.stop_event.clear()

        def spawn_c_client(self):
            '''Spawn C client to create QRNG Fifo'''
            c_client_path = os.path.join(
                os.path.dirname(
                    os.path.dirname(
                        os.path.dirname(
                            os.path.dirname(
                                os.path.realpath(__file__))))),
                'src-c', 'wesqrngd', 'wesqrngd')

            logging.debug('Spawing fifo_c_client: %s', c_client_path)

            if os.path.exists(self.fifo_path):
                os.remove(self.fifo_path)

            devnull = open('/dev/null', 'w')
            self.c_client = Popen([c_client_path, str(self.fifo_number)],
                                  stdout=devnull, stderr=devnull)

        def run(self):
            '''Create connection'''
            logging.debug("Looking for file: %s", self.fifo_path)
            while not os.path.exists(self.fifo_path):
                time.sleep(.1)

            logging.debug("Found file: %s", self.fifo_path)

            self.init_event.set()

            try:
                with open(self.fifo_path, 'rb') as fifo:
                    while not self.stop_event.is_set():
                        if (self.buff.bytes_needed() >
                                QRNGSource.READ_SIZE):
                            new_data = fifo.read(QRNGSource.READ_SIZE)
                            with self.lock:
                                self.buff.add_random_data(
                                    new_data)
                        time.sleep(0)
            except IOError as error:
                logging.warning("Error reading from FIFO, resetting: %s",
                                error)
    #pylint: enable=E1101,R0913
#pylint: enable=R0902
