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

'''WES Entropy Engine'''

import logging
import time
import WesEntropy.Engine.utilities as utilities
import WesEntropy.Engine.sp800_90a as sp800_90a
import WesEntropy.Engine.entropysource as entropysource

VERSION = '1.0'

#pylint: disable=R0903
class EntropyEngine(object):
    '''
    Construct an entropy engine of the following form:

          drbg_source          raw_source
               |                   |
               | (rate)            |
               V                   V
             drbg---------------->XOR
                                   |
                                   |
                                   V
                               rand_bits

    This abstracts all the constructions in NIST SP800-90C, while also
    allowing for other implementations as needed.
    The sources are to be EntropySource objects, or a specification for
    constructing an EntropySource object. The rate at which the DRBG is
    to be reseeded can be numeric, indicating the number of times we
    can pull bits from the source before we reseed, or one of the
    following string values:

    MINIMAL   : Go the longest that NIST SP800-90A allows in this case.
    LINESPEED : Put in one bit of entropy for each bit we take out.
    '''

    def __init__(self, drbg_spec, drbg_source, drbg_reseed_rate, raw_source):
        self.drbg = None
        self.raw = None

        if drbg_spec is not None and drbg_source is not None:
            self.drbg = sp800_90a.new(drbg_spec, drbg_source, drbg_reseed_rate)

        if raw_source is not None:
            self.raw  = entropysource.new(raw_source)

        self.total_bytes = 0
        self.start_time = time.time()

        if not self.drbg and not self.raw:
            raise ValueError(
                'Cannot construct engine with neither DRBG nor raw source.')

    def get_stats(self):
        '''Get statistics on amount of entropy consumed/produced'''
        stats = {'info': {},
                 'consumed': {},
                 'produced': {}}

        stats['info']['engine_uptime'] = time.time() - self.start_time
        stats['info']['version'] = VERSION

        if self.raw is not None:
            stats['info']['stream'] = self.raw.get_name()

        if self.drbg is not None:
            stats['info']['seed'] = self.drbg.entropy_source.get_name()
            stats['info']['drbg'] = self.drbg.get_name()

        stats['consumed'] = entropysource.get_all_stats()
        stats['produced'] = self.total_bytes

        return stats

    def cleanup(self):
        '''Uninstantiate DRBG and close any raw entropy source'''
        if self.drbg:
            self.drbg.uninstantiate()
        if self.raw:
            self.raw.close_entropy_source()

    #pylint: disable=R0911
    def generate(self, n_bits, security_strength = None,
                 prediction_resistance = None, additional_input = ''):
        'Generate bits from the entropy engine.'
        #
        # If we have a DRBG then use it

        if self.drbg:
            status, drbg_bits = self.drbg.generate(
                n_bits, security_strength,
                prediction_resistance, additional_input)

            # The DRBG, once instantiated, should never fail
            if status != 'SUCCESS' and status != 'RESEED_FAILED':
                return status, "DRBG  failed"

            # If we are combining the DRBG with raw input then get raw bits
            if self.raw:
                status, raw_bits = self.raw.get_entropy_input(
                    security_strength, n_bits,
                    n_bits, prediction_resistance)

                # Failure here is allowable, because we still have the DRBG
                if status != 'SUCCESS':
                    logging.debug(
                        "Using drbg only. %s, %s", status, raw_bits)
                    self.total_bytes += len(drbg_bits)
                    return 'DRBG_ONLY', drbg_bits

                # If we have both sources working then XOR them together
                comb_bits = utilities.binstr_xor(drbg_bits, raw_bits)
                self.total_bytes += len(comb_bits)
                return 'SUCCESS', comb_bits

            # If we only have a DRBG, then return just those bits
            else:
                self.total_bytes += len(drbg_bits)
                return 'SUCCESS', drbg_bits

        # If we have no DRBG then we must have a raw entropy source
        elif self.raw:
            status, raw_bits = self.raw.get_entropy_input(
                security_strength, n_bits,
                n_bits, prediction_resistance)

            # If this fails with no DRBG to back it up, return an error
            if status != 'SUCCESS':
                return status, "Raw source failed"

            # Otherwise return the raw bits
            self.total_bytes += len(raw_bits)
            return 'SUCCESS', raw_bits

        # If we have neither DRBG nor raw source, we cannot generate bits
        return 'ERROR', "Neither DRBG nor raw source available"

    #pylint: enable=R0911

