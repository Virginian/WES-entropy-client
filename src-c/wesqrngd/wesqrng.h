///////////////////////////////////////////////////////////////////////////////
//
// Module: wesqrng.h
// Standard: 1.0
//
// Copyright 2014-2015 Whitewood Encryption Systems, Inc.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Purpose: This file contains the QRNG library interface definition.
//
///////////////////////////////////////////////////////////////////////////////
#ifndef WESQRNG_H
#define WESQRNG_H

// T Y P E D E F S
// A handle to an instance of trhe library.
typedef unsigned long   thWesQrng;

// Version parameter structure.
typedef struct
{
    unsigned char uMajor;
    unsigned char uMinor;
    unsigned char uBuild;
    char          confidence;
} trVersion;

// E N U M S
// The library instance operating mode.
typedef enum
{
   eWesQrngModeDefault = 0
} teWesQrngMode;

// Unique parameter identifier for get/set functions.
typedef enum
{
    eWesQrngParameterVersion = 0
} teWesQrngParameter;

// List of library API errors.
typedef enum
{
    eWesQrngErrorNone = 0,
    eWesQrngErrorNotSupported,
    eWesQrngErrorHandle,
    eWesQrngErrorOutOfResources,
    eWesQrngErrorParameter,
    eWesQrngErrorTruncation,
    eWesQrngErrorEntropy,
    eWesQrngErrorDeviceName,
    eWesQrngErrorInvalidMode,
    eWesQrngErrorUnknown
} teWesQrngError;

// P U B L I C  F U N C T I O N S
#ifdef __cplusplus
extern "C" {
#endif

//
//         Name: wesQrngCreate
//
//  Description: Create an instance of the library.
// 
//       pcName: pointer to constant null terminated string containing the 
//               name of the QRNG device driver board instance, e.g., "0".
//       phQrng: pointer to library instance handle
//        eMode: library operating mode
//
//       Return: enumerated error value
//
//  Constraints: There is an upper bound on the number of library instances 
//               that can be instantiated.
//
teWesQrngError wesQrngCreate(const char *pcName, thWesQrng *phQrng, 
                             const teWesQrngMode eMode);

//
//         Name: wesQrngEntropyGet
//
//  Description: Retrieve buffer containing conditioned random data.
// 
//        hQrng: valid library instance handle
//      pBuffer: pointer to preallocated buffer
//   uMaxLength: size of preallocated buffer in bytes
//     puLength: pointer to preallocated length variable
//
//       Return: enumerated error value
//
//  Constraints: The entropy data length may be less than the the maximum
//               specified length.
//
teWesQrngError wesQrngEntropyGet(const thWesQrng hQrng, void *pBuffer,
                                 const unsigned long uMaxLength, 
                                 unsigned long *puLength);

//
//         Name: wesQrngNoiseGet
//
//  Description: Retrieve buffer containing unconditioned random data.
// 
//        hQrng: valid library instance handle
//      pBuffer: pointer to preallocated buffer
//   uMaxLength: size of preallocated buffer in bytes
//     puLength: pointer to preallocated length variable
//
//       Return: enumerated error value
//
//  Constraints: The entropy data length may be less than the the maximum
//               specified length.
//
teWesQrngError wesQrngNoiseGet(const thWesQrng hQrng, void *pBuffer,
                               const unsigned long uMaxLength, 
                               unsigned long *puLength);


//
//         Name: wesQrngDestroy
//
//  Description: Destroy previously created library instance.
// 
//        hQrng: valid library instance handle
//
//       Return: enumerated error value
//
//  Constraints: None have been identified.
//
teWesQrngError wesQrngDestroy(const thWesQrng hQrng);

//
//         Name: wesQrngParameterSet
//
//  Description: Set library instance parameter.
// 
//        hQrng: valid library instance handle
//   eParameter: enumerated parameter value
//     pcBuffer: pointer to preallocated parameter specific data buffer
//      uLength: size of parameter data in bytes
//
//       Return: enumerated error value
//
//  Constraints: The buffer length must be valid for the specified parameter.
//
teWesQrngError wesQrngParameterSet(const thWesQrng hQrng, 
                                   const teWesQrngParameter eParameter,
                                   const void *pcBuffer, 
                                   const unsigned long uLength);

//
//         Name: wesQrngParameterGet
//
//  Description: Get library instance parameter.
// 
//        hQrng: valid library instance handle
//   eParameter: enumerated parameter value
//      pBuffer: pointer to preallocated parameter specific data buffer
//      uLength: length of preallocated data buffer
//
//       Return: enumerated error value
//
//  Constraints: The buffer length must be valid for the specified parameter.
//
teWesQrngError wesQrngParameterGet(const thWesQrng hQrng,
                                   const teWesQrngParameter eParameter,
                                   void *pBuffer, 
                                   const unsigned long uLength);

//
//         Name: wesQrngErrorStringGet
//
//  Description: Retrieve human readable string associated with the specified 
//               error.
// 
//       eError: enumerater error value
//      pBuffer: pointer to preallocated buffer
//      uLength: length of preallocated buffer in bytes
//
//       Return: enumerated error value
//
//  Constraints: None have been identified.
//
teWesQrngError wesQrngErrorStringGet(const teWesQrngError eError, char *pBuffer,
                                     const unsigned long uLength);

#ifdef __cplusplus
}
#endif

#endif // WESQRNG_H
