///////////////////////////////////////////////////////////////////////////////
//
// Module: wesengine.h
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
// Purpose: This file contains the WES Entropy Engine library interface 
//          definition.
//
///////////////////////////////////////////////////////////////////////////////

#ifndef WESENGINE_H
#define WESENGINE_H

// TYPEDEFS
// A handle to a session with the WES Entropy engine.
typedef unsigned long thWesEngine;

// Error code.
typedef unsigned int tWesEngineError;


// DEFINES
#define WES_ENGINE_ERROR_NONE ((tWesEngineError) 0)


// PUBLIC  FUNCTIONS

//
//         Name: wesEngineCreate
//
//  Description: Create a session with the WES Entropy Engine library.
// 
//     phEngine: pointer to library session handle
// pcConfigPath: pointer to constant null terminated string containing the 
//               path to the WES Entropy configuration file
//               If a NULL path is used, the engine will use a fixed known
//               location configuration file.  If there is no configuration 
//               file in the fixed location, the engine will use a fixed 
//               default configuration.  
//               If a path is received, but cannot be read, the call will 
//               return an error.
//
//       Return: error code
//               WES_ENGINE_ERROR_NONE on success
//
//  Constraints: There is an upper bound on the number of library sessions
//               that can be instantiated.
//
tWesEngineError wesEngineCreate(const char *pcConfigPath, 
                                thWesEngine *phEngine);


//
//         Name: wesEngineGetBytes
//
//  Description: Retrieve buffer containing crytpographically strong 
//               pseudorandom bytes.  
//               Error occurs if there is insufficient entropy to ensure an 
//               unpredictable byte sequence.
// 
//      hEngine: valid library session handle
//      pBuffer: pointer to preallocated buffer
//   uMaxLength: size of preallocated buffer in bytes
//     puLength: pointer to preallocated length variable
//
//       Return: error code
//               WES_ENGINE_ERROR_NONE on success
//
//  Constraints: The return buffer length may be less than the the maximum
//               specified length.
//
tWesEngineError wesEngineGetBytes(const thWesEngine hEngine, 
                                void *pBuffer,
                                const unsigned long uMaxLength, 
                                unsigned long *puLength);


//
//         Name: wesEngineGetPseudoBytes
//
//  Description: Retrieve buffer containing pseudorandom bytes.
// 
//      hEngine: valid library session handle
//      pBuffer: pointer to preallocated buffer
//   uMaxLength: size of preallocated buffer in bytes
//     puLength: pointer to preallocated length variable
//
//       Return: error code
//               WES_ENGINE_ERROR_NONE on success
//
//  Constraints: The returned buffer length may be less than the the maximum
//               specified length.
//
tWesEngineError wesEngineGetPseudorandomBytes(const thWesEngine hEngine, 
                                void *pBuffer,
                                const unsigned long uMaxLength, 
                                unsigned long *puLength);


//
//         Name: wesEngineStatus
//
//  Description: Get status of this library session.
//               iStatus = 1, if the session has sufficient randomness
//                         0, otherwise
//               
//      hEngine: valid library session handle
//     piStatus: pointer to status integer
//
//       Return: error code
//               WES_ENGINE_ERROR_NONE on success
//
//  Constraints: None have been identified.
//
tWesEngineError wesEngineGetStatus(const thWesEngine hEngine, int * piStatus);


//
//         Name: wesEngineDestroy
//
//  Description: Destroy previously created library session.
// 
//      hEngine: valid library session handle
//
//       Return: error code
//               WES_ENGINE_ERROR_NONE on success
//
//  Constraints: None have been identified.
//
tWesEngineError wesEngineDestroy(const thWesEngine hEngine);


//
//         Name: wesEngineErrorStringGet
//
//  Description: Retrieve human readable string associated with the specified 
//               error.
// 
//       eError: error code
//      pBuffer: pointer to preallocated buffer
//      uLength: length of preallocated buffer in bytes
//
//       Return: error code
//               WES_ENGINE_ERROR_NONE on success
//
//  Constraints: None have been identified.
//
tWesEngineError wesEngineErrorStringGet(const tWesEngineError eError, 
                                char *pBuffer,
                                const unsigned long uLength);

#endif // WESENGINE_H
