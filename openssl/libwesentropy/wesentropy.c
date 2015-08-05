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

#include <stdio.h>
#include "Python.h"
#include "vendor/wesengine.h"

static thWesEngine ctx = 0;
static PyObject * pModule;

static char *errors[] = {
  "none",
#define				ERROR_FILE_NOT_FOUND	1
  "Randomness not available",
#define				ERROR_READ_ERROR	2
  "Randomness couldn't be fetched",
#define				ERROR_INVALID_CONTEXT	3
  "Incorrect context"
};


/* 
 * Create session connected to WES Entropy Daemon.
 */
tWesEngineError wesEngineCreate(const char *pcConfigPath, 
				thWesEngine *phEngine)
{   
    PyObject *pName, *pFunc, *pArgs, *pResult;
    long retval = WES_ENGINE_ERROR_NONE;
    
    if (ctx == 0) {
        ctx = (thWesEngine) 1;
        *phEngine = ctx;
        Py_Initialize();
        pName = PyString_FromString("WesEntropy.Client.client");
        if (pName == NULL) {
            goto err;
        }
        pModule = PyImport_Import(pName);
        if (pModule == NULL) {
            goto err;
        }
        
        Py_DECREF(pName);
        
        pFunc = PyObject_GetAttrString(pModule, "initialize");
        if (pFunc == NULL) {
            goto err;
        }
        pArgs = PyTuple_New(0);
        if (pArgs == NULL) {
            goto err;
        }
        
        pResult = PyObject_CallObject(pFunc, pArgs);
        if (pResult == NULL) {
            goto err;
        }
        Py_DECREF(pArgs);
        Py_DECREF(pFunc);
    
        retval = PyInt_AsLong(pResult);
        Py_DECREF(pResult);
    }
    return retval;

  err:
    PyErr_Print();
    Py_Finalize();
    return ERROR_READ_ERROR;
}

/* 
 * Return uMaxLength random bytes from WES Entropy Daemon.
 */
tWesEngineError wesEngineGetBytes(const thWesEngine hEngine, 
				  void *pBuffer,
				  const unsigned long uMaxLength,
				  unsigned long *puLength)
{
    PyObject *pFunc, *pValue, *pArgs, *pResult;
    char *data;
    unsigned long i;
    Py_ssize_t data_size;
    tWesEngineError ret;
    
    if (hEngine != ctx)
        return ERROR_INVALID_CONTEXT;
    
    pFunc = PyObject_GetAttrString(pModule, "get_bytes");
    if (pFunc == NULL) {
        goto err;
    }
    
    pValue = PyInt_FromLong(uMaxLength);
    if (pValue == NULL) {
        goto err;
    }
    
    pArgs = PyTuple_New(1);
    if (pArgs == NULL) {
        goto err;
    }
    
    PyTuple_SetItem(pArgs, 0, pValue);
    
    pResult = PyObject_CallObject(pFunc, pArgs);
    if (pResult == NULL) {
        goto err;
    }
    
    Py_DECREF(pFunc);
    Py_DECREF(pArgs);
    
    data_size = PyString_Size(pResult);
    if (data_size == 0) {
        ret = ERROR_READ_ERROR;
        *puLength = 0;
    } else {
    
        ret = WES_ENGINE_ERROR_NONE;
        data = PyString_AsString(pResult);
    
        if (data == NULL) {
            goto err;
        }
    
        for (i = 0; i < data_size; i ++) {
            ((char*)pBuffer)[i] = data[i];
        }
    
        *puLength = data_size;
    }
    Py_DECREF(pResult);
    return ret;
  err:
    PyErr_Print();
    Py_Finalize();
    return ERROR_READ_ERROR;   
}

/* 
 * Return uMaxLength pseudorandom bytes.
 */
tWesEngineError wesEngineGetPseudorandomBytes(const thWesEngine hEngine, 
					      void *pBuffer,
					      const unsigned long uMaxLength,
					      unsigned long *puLength)
{
    return wesEngineGetBytes(hEngine, pBuffer, uMaxLength, puLength);
}

/*
 * Destroy the engine associated with hEngine.
 */
tWesEngineError wesEngineDestroy(const thWesEngine hEngine)
{
    PyObject *pFunc, *pArgs;

    if (hEngine != ctx)
        return ERROR_INVALID_CONTEXT;

    pFunc = PyObject_GetAttrString(pModule, "destroy");
    if (pFunc == NULL) {
        goto err;
    }
    pArgs = PyTuple_New(0);
    if (pArgs == NULL) {
        goto err;
    }
    
    PyObject_CallObject(pFunc, pArgs);
    Py_DECREF(pArgs);
    Py_DECREF(pFunc);
    
    Py_DECREF(pModule);
    Py_Finalize();

    ctx = 0;
    return WES_ENGINE_ERROR_NONE;
  err:
    PyErr_Print();
    Py_Finalize();
    return ERROR_READ_ERROR; 
}

/* 
 * Return a human-readable string describing eError.
 */
tWesEngineError wesEngineErrorStringGet(const tWesEngineError eError, 
					char *pBuffer,
					const unsigned long uLength)
{
    snprintf(pBuffer, uLength-1, "ERROR %d: %s\n", eError, errors[eError]);
    pBuffer[uLength-1] = '\0';
    return WES_ENGINE_ERROR_NONE;
}
