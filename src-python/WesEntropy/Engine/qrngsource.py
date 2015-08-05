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

'''WES Qrng Entropy Source'''

import logging
import WesEntropy.Engine.utilities as utilities
import WesEntropy.Engine.entropysource as entropysource
from WesEntropy.Engine.wesqrng import WesQrng, eWesQrngError

class QRNGSource(entropysource.EntropySource):
    '''Entropy source based on QRNG'''
    def __init__(self, device_name):
        entropysource.EntropySource.__init__(self)
        self.qrng = WesQrng()
        self.device_name = device_name
        try:
            self.qrng.wesQrngCreate(self.device_name, "eWesQrngModeDefault")
        except eWesQrngError as error:
            logging.error(error.msg)
            raise

    def get_name(self):
        '''Get name of entropy source for use in statistics'''
        return 'QRNG%s' % self.device_name

    def get_entropy_input(self, security_strength,
                          min_bits, max_bits,
                          prediction_resistance):
        min_bytes = (min_bits + 7) / 8
        try:
            ctr = 0
            random_bytes = ''
            while len(random_bytes) < min_bytes and ctr < 10:
                random_bytes += (
                    self.qrng.wesQrngEntropyGet(min_bytes - len(random_bytes)))
                ctr += 1

            logging.debug("Got %s bytes from qrng.", len(random_bytes))

            random_bytes = utilities.binstr_leftmost(random_bytes, max_bits)

            if len(random_bytes) >= min_bytes:
                self.total_bytes += len(random_bytes)
                return 'SUCCESS', random_bytes
            else:
                return 'ERROR', ("Unable to get the requested entropy. " +
                                 "Only got %s bytes." % len(random_bytes))
        except eWesQrngError as error:
            logging.error(error.msg)
            raise

    def close_entropy_source(self):
        self.qrng.wesQrngDestroy()

