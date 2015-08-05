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

'''WES Entropy Source'''

import sys
import logging
import WesEntropy.Engine.utilities as utilities

#pylint: disable=C0103
try:
    #pylint: disable=F0401
    import rdrand
    #pylint: enable=F0401
except SystemError:
    rdrand = None
except ImportError:
    rdrand = False

entropy_sources_by_spec = {}

entropy_specs = {
    'FILE_dev_random'     : ('FILE', '/dev/random',  True),
    'FILE_dev_urandom'    : ('FILE', '/dev/urandom', False),
    'HARDWARE_RDRAND'     : ('HARDWARE', 'RDRAND', True),
    'HARDWARE_QRNG_0'     : ('HARDWARE', 'QRNG', '0', True),
    'DEBUG_DETERMINISTIC' : ('DEBUG', 'deterministic', False),
}

#pylint: enable=C0103

def get_all_stats():
    '''Return number of bytes total taken all entropy sources'''
    stats = {}
    for source in entropy_sources_by_spec.itervalues():
        stats[source.get_name()] = source.total_bytes
    return stats

class EntropySource(object):
    '''
    An abstract class for entropy sources.
    '''

    def __init__(self):
        self.total_bytes = 0

    def get_name(self):
        '''Get name of entropy source for use in statistics'''
        raise NotImplementedError

    def get_entropy_input(self, security_strength,
                          min_bits, max_bits,
                          prediction_resistance):
        '''Get entropy input from source'''
        raise NotImplementedError

    def close_entropy_source(self):
        '''Close entropy source'''
        raise NotImplementedError

class FileEntropySource(EntropySource):
    '''
    An entropy source based on a file or file-like device.'
    '''

    def __init__(self, path, supports_prediction_resistance):
        '''Open up a file.'''
        EntropySource.__init__(self)

        self.supports_prediction_resistance = supports_prediction_resistance
        self.entropy_source_path            = path
        self.entropy_source_file            = file(path, 'rb')
        return

    def __del__(self):
        '''Close the file again.'''
        self.close_entropy_source()
        return

    def get_name(self):
        '''Get name of entropy source for use in statistics'''
        return 'File: %s' % self.entropy_source_path

    def get_entropy_input(self, security_strength,
                          min_bits, max_bits,
                          prediction_resistance):
        '''Return entropy from a file.'''

        if prediction_resistance and not self.supports_prediction_resistance:
            return 'ERROR', 'Source does not support prediction resistance.'

        if (not hasattr(self, 'entropy_source_file') or
                not self.entropy_source_file or
                self.entropy_source_file.closed):
            self.entropy_source_file = file(self.entropy_source_path, 'rb')

        n_bytes = (min_bits + 7) / 8
        try:
            random_bytes = self.entropy_source_file.read(n_bytes)
        except IOError as err:
            return 'ERROR', ('IOError: %s' % str(err))

        if len(random_bytes) < n_bytes:
            return 'ERROR', ('Only received %i bytes' % len(random_bytes))

        random_bytes = utilities.binstr_leftmost(random_bytes, max_bits)

        self.total_bytes += len(random_bytes)
        return 'SUCCESS', random_bytes

    def close_entropy_source(self):
        '''Close file entropy source'''
        if (hasattr(self, 'entropy_source_file') and
                self.entropy_source_file and
                not self.entropy_source_file.closed):
            self.entropy_source_file.close()
        return

class RdRandEntropySource(EntropySource):
    '''
    An entropy source based on the Intel RdRand instruction.'
    '''


    def __init__(self):
        '''Detect presence of the RdRand instruction.'''
        EntropySource.__init__(self)

        self.supports_prediction_resistance = True

        if rdrand is None:
            raise ValueError(
                'The RdRand instruction is not present on this CPU.')
        elif rdrand is False:
            raise ValueError(
                'The python module rdrand is not present on this system.')
        return

    def get_name(self):
        '''Get name of entropy source for use in statistics'''
        return 'RdRand'

    def get_entropy_input(self, security_strength,
                          min_bits, max_bits,
                          prediction_resistance):
        '''Return entropy from the rdrand instruction.'''

        if rdrand is None:
            return ('ERROR',
                    'The RdRand instruction is not present on this CPU')
        elif rdrand is False:
            return ('ERROR',
                    'The python module rdrand is not present on this system')
        else:
            try:
                n_bytes = (min_bits + 7) / 8
                #pylint: disable=E1103
                random_bytes = rdrand.rdrand_get_bytes(n_bytes)
                #pylint: enable=E1103
                random_bytes = utilities.binstr_leftmost(
                    random_bytes, max_bits)

                self.total_bytes += len(random_bytes)
                return ('SUCCESS', random_bytes)
            except StandardError:
                return ('ERROR', 'Unable to draw bytes from RdRand')

    def close_entropy_source(self):
        '''Close RdRand source (NOOP)'''
        return

class DeterministicSource(EntropySource):
    '''Deterministic entropy source - for debugging only'''
    def __init__(self):
        EntropySource.__init__(self)
        self.block = '0123456789'
        self.data_pending = ''

    def get_name(self):
        '''Get name of entropy source for use in statistics'''
        return 'Deterministic'

    def get_entropy_input(self, security_strength,
                          min_bits, max_bits,
                          prediction_resistance):
        min_bytes = (min_bits + 7)/8
        blocks_needed = (
            (min_bytes - len(self.data_pending) + len(self.block) - 1) /
            len(self.block))
        random_bytes = self.data_pending + self.block * blocks_needed

        self.data_pending = random_bytes[min_bytes:]

        random_bytes = random_bytes[0:min_bytes]
        random_bytes = utilities.binstr_leftmost(random_bytes, max_bits)

        self.total_bytes += len(random_bytes)

        return 'SUCCESS', random_bytes

    def close_entropy_source(self):
        self.data_pending = ''


def get_valid_source():
    '''Returns a valid (non-network) source of randomness.

    This source may be used by a function that itself requires randomness.'''
    return new(('FILE', '/dev/urandom', False))


#pylint: disable=R0912
def new(source_spec):
    '''Instantiate a new source or retrieve an existing one.'''

    # If given a string, use that to retrieve the full spec.
    if source_spec in entropy_specs:
        source_spec = entropy_specs[source_spec]

    # By this point, we should have something that can be coerced into a tuple.
    if source_spec is None:
        return None
    source_spec = tuple(source_spec)

    # If the spec has already been instantiated, retrieve that source.
    if source_spec in entropy_sources_by_spec:
        return entropy_sources_by_spec[source_spec]

    # Go through the possibilities for the source type.
    source = None
    if source_spec[0].upper() == 'FILE':
        try:
            if len(source_spec) >= 3:
                pr_flag = source_spec[2]
            else:
                pr_flag = False
            source = FileEntropySource(source_spec[1], pr_flag)
        except StandardError:
            pass
    elif source_spec[0].upper() == 'HARDWARE':
        if source_spec[1].upper() == 'RDRAND':
            source = RdRandEntropySource()
        elif source_spec[1].upper() == 'QRNG':
            try:
                import WesEntropy.Engine.qrngfifosource as qrngsource
            except ImportError:
                logging.error("Error importing the QRNG entropy source module.")
                sys.exit(1)
            source = qrngsource.QRNGSource(source_spec[2])
    elif source_spec[0].upper() == 'ENTROPY SERVER':
        try:
            import WesEntropy.Engine.networksource as networksource
        except ImportError:
            # If module isnt' found, log and exit gracefully
            logging.error("Error importing the network entropy source module.")
            sys.exit(1)

        try:
            logging.debug("Setting up network entropy from %s.  "
                          "Client id: %s, HMAC: %s",
                          source_spec[1], source_spec[2], source_spec[3])
            source = networksource.NetworkEntropySource(
                source_spec[1], source_spec[2], source_spec[3])
        except StandardError:
            pass
    elif source_spec[0].upper() == 'DEBUG':
        logging.critical("***DEBUG ONLY***: Entropy source is deterministic")
        source = DeterministicSource()
    else:
        logging.critical(
            "Bad entropy source specification: %s", str(source_spec))
    entropy_sources_by_spec[source_spec] = source
    return source

#pylint: enable=R0912
