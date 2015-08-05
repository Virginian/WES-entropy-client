// Copyright (c) 2014-2015 The OpenSSL Project.  All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer. 
// 
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
// 
// 3. All advertising materials mentioning features or use of this
//    software must display the following acknowledgment:
//    "This product includes software developed by the OpenSSL Project
//    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
// 
// 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
//    endorse or promote products derived from this software without
//    prior written permission. For written permission, please contact
//    openssl-core@openssl.org.
// 
// 5. Products derived from this software may not be called "OpenSSL"
//    nor may "OpenSSL" appear in their names without prior written
//    permission of the OpenSSL Project.
// 
// 6. Redistributions of any form whatsoever must retain the following
//    acknowledgment:
//    "This product includes software developed by the OpenSSL Project
//    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
// 
// THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
// EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
// ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
// OF THE POSSIBILITY OF SUCH DAMAGE.

#ifdef EWES_DEBUG
#include <stdlib.h>
#include <stdio.h>
#endif
#include <string.h>
#include <openssl/engine.h>
#include <openssl/dso.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "vendor/wesengine.h"

#define EWES_LIB_NAME "WES engine"
#include "ewes_err.c"

#define WESENTROPY "wesentropy"

/* ------------------------------------------------------------ */
/*
 * Constants used when creating the engine
 */

static const char *ewes_id = "ewes";
static const char *ewes_name = "Whitewood Quantum RNG engine support";

/*
 * Functions to handle the engine
 */

static thWesEngine ewes_context = 0;
static int ewes_init(ENGINE *e);
static int ewes_finish(ENGINE *e);
static int ewes_destroy(ENGINE *e);
static int ewes_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) ());

#define EWES_CMD_SO_PATH ENGINE_CMD_BASE
static const ENGINE_CMD_DEFN ewes_cmd_defns[] = {
    {EWES_CMD_SO_PATH,
     "SO_PATH",
     "Specifies the path to the 'wesentropy' shared library",
     ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}
};

/*
 * Functions to handle the mutexes
 */
/* The impossible lock id is one that OpenSSL will certainly never
   use.  The dynamic locks have negative lock ids, and the none-dynamic
   ones are only 42 for the moment, increasing very slowly. */
#define EWES_IMPOSSIBLE_LOCK_ID	4711
static int ewes_lockid = EWES_IMPOSSIBLE_LOCK_ID;
static int ewes_mutex_init(int * lockid);
static int ewes_mutex_lock(int lockid);
static int ewes_mutex_unlock(int lockid);
static int ewes_mutex_destroy(int * lockid);

/* ------------------------------------------------------------ */
/*
 * RAND functions and method structure
 */

static int ewes_rand_bytes(unsigned char *buf, int num);
static int ewes_rand_pseudobytes(unsigned char *buf, int num);
static int ewes_rand_status(void);

static RAND_METHOD ewes_rand = {
  NULL,
  ewes_rand_bytes,
  NULL,
  NULL,
  ewes_rand_pseudobytes,
  ewes_rand_status,
};

/* ------------------------------------------------------------ */
/*
 * Functions to handle the engine
 */
static int bind_ewes(ENGINE *e)
{
  if (!ewes_mutex_init(&ewes_lockid))
    return 0;

  if (!ENGINE_set_id(e, ewes_id) ||
      !ENGINE_set_name(e, ewes_name) ||
      !ENGINE_set_RAND(e, &ewes_rand) ||
      !ENGINE_set_destroy_function(e, ewes_destroy) ||
      !ENGINE_set_init_function(e, ewes_init) ||
      !ENGINE_set_finish_function(e, ewes_finish) ||
      !ENGINE_set_ctrl_function(e, ewes_ctrl) ||
      !ENGINE_set_cmd_defns(e, ewes_cmd_defns))
    return 0;

  /* Ensure the ewes error handling is set up */
  ERR_load_EWES_strings();
  return 1;
}

static int bind_fn(ENGINE *e, const char *id)
{
  if (id && (strcmp(id, ewes_id) != 0))
    return 0;
  if (!bind_ewes(e))
    return 0;
  return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)

/*
 * This is a process-global DSO handle used for loading and unloading
 * the wesentropy library. NB: This is only set (or unset) during an
 * init () or finish () call (reference counts permitting) and they're
 * operating with global locks, so this should be thread-safe
 * implicitly.
 */
static DSO *ewes_dso = NULL;
static const char *WESENTROPY_LIBNAME = WESENTROPY;

typedef tWesEngineError t_wesEngineCreate(const char *pcConfigPath, 
					  thWesEngine *phEngine);
typedef tWesEngineError t_wesEngineGetBytes(const thWesEngine hEngine, 
					    void *pBuffer,
					    const unsigned long uMaxLength,
					    unsigned long *puLength);
typedef tWesEngineError t_wesEngineGetPseudorandomBytes(const thWesEngine hEngine, 
							void *pBuffer,
							const unsigned long uMaxLength,
                                unsigned long *puLength);
typedef tWesEngineError t_wesEngineDestroy(const thWesEngine hEngine);
typedef tWesEngineError t_wesEngineErrorStringGet(const tWesEngineError eError, 
						  char *pBuffer,
						  const unsigned long uLength);

static t_wesEngineCreate *p_wesEngineCreate = NULL;
static char str_wesEngineCreate[] = "wesEngineCreate";
static t_wesEngineGetBytes *p_wesEngineGetBytes = NULL;
static char str_wesEngineGetBytes[] = "wesEngineGetBytes";
static t_wesEngineGetPseudorandomBytes *p_wesEngineGetPseudorandomBytes = NULL;
static char str_wesEngineGetPseudorandomBytes[] = "wesEngineGetPseudorandomBytes";
static t_wesEngineDestroy *p_wesEngineDestroy = NULL;
static char str_wesEngineDestroy[] = "wesEngineDestroy";
static t_wesEngineErrorStringGet *p_wesEngineErrorStringGet = NULL;
static char str_wesEngineErrorStringGet[] = "wesEngineErrorStringGet";

/* Initiator which is only present to make sure this engine looks available */
static int ewes_init(ENGINE *e)
{
  int to_return = 0;		/* assume failure */
  tWesEngineError ret = WES_ENGINE_ERROR_NONE;

  if (ewes_dso != NULL) {
    EWESerr(EWES_F_EWES_INIT, EWES_R_ALREADY_LOADED);
    goto err;
  }
  /*
   * Trying to load the Library "wesentropy"
   */
  ewes_dso = DSO_load(NULL, WESENTROPY_LIBNAME, NULL, 0);
  if (ewes_dso == NULL) {
    EWESerr(EWES_F_EWES_INIT, EWES_R_DSO_FAILURE);
    goto err;
  }

  /*
   * Trying to load Function from the Library
   */
  if (!(p_wesEngineCreate = (t_wesEngineCreate *)
	DSO_bind_func(ewes_dso, str_wesEngineCreate))
      || !(p_wesEngineGetBytes = (t_wesEngineGetBytes *)
	   DSO_bind_func(ewes_dso, str_wesEngineGetBytes))
      || !(p_wesEngineGetPseudorandomBytes = (t_wesEngineGetPseudorandomBytes *)
	   DSO_bind_func(ewes_dso, str_wesEngineGetPseudorandomBytes))
      || !(p_wesEngineDestroy = (t_wesEngineDestroy *)
	   DSO_bind_func(ewes_dso, str_wesEngineDestroy))
      || !(p_wesEngineErrorStringGet = (t_wesEngineErrorStringGet *)
	   DSO_bind_func(ewes_dso, str_wesEngineErrorStringGet))) {
    EWESerr(EWES_F_EWES_INIT, EWES_R_DSO_FAILURE);
    goto err;
  }

  ret = p_wesEngineCreate(NULL, &ewes_context);
  if (ret != WES_ENGINE_ERROR_NONE) {
    char error_buffer[1024];

    ret = p_wesEngineErrorStringGet(ret, error_buffer, sizeof(error_buffer));
    EWESerr(EWES_F_EWES_INIT, EWES_R_REQUEST_FAILED);
    if (ret == WES_ENGINE_ERROR_NONE)
      ERR_add_error_data(1, error_buffer);
    goto err;
  }

  return 1;
 err:
  if (ewes_dso) {
    DSO_free(ewes_dso);
  }
  ewes_dso = NULL;
  p_wesEngineCreate = NULL;
  p_wesEngineGetBytes = NULL;
  p_wesEngineGetPseudorandomBytes = NULL;
  p_wesEngineDestroy = NULL;
  p_wesEngineErrorStringGet = NULL;

  return 0;
}

/* Finisher which is only present to make sure this engine looks available */
static int ewes_finish(ENGINE *e)
{
  int to_return = 0;		/* assume failure */
  tWesEngineError ret = WES_ENGINE_ERROR_NONE;

  ret = p_wesEngineDestroy(ewes_context);
  if (ret != WES_ENGINE_ERROR_NONE) {
    char error_buffer[1024];

    ret = p_wesEngineErrorStringGet(ret, error_buffer, sizeof(error_buffer));
    EWESerr(EWES_F_EWES_INIT, EWES_R_REQUEST_FAILED);
    if (ret == WES_ENGINE_ERROR_NONE)
      ERR_add_error_data(1, error_buffer);
    return 0;
  }

  if (ewes_dso == NULL) {
    EWESerr(EWES_F_EWES_FINISH, EWES_R_NOT_LOADED);
    return 0;
  }
  if (!DSO_free(ewes_dso)) {
    EWESerr(EWES_F_EWES_FINISH, EWES_R_DSO_FAILURE);
    return 0;
  }

  ewes_dso = NULL;

  p_wesEngineCreate = NULL;
  p_wesEngineGetBytes = NULL;
  p_wesEngineGetPseudorandomBytes = NULL;
  p_wesEngineDestroy = NULL;
  p_wesEngineErrorStringGet = NULL;

  return 1;
}

static int ewes_destroy(ENGINE *e)
{
    ERR_unload_EWES_strings();
    ewes_mutex_destroy(&ewes_lockid);
    return 1;
}

static int ewes_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) ())
{
  if (ewes_mutex_lock(ewes_lockid)) {
    int to_return = 0;		/* assume failure */
    int initialised = ((ewes_dso == NULL) ? 0 : 1);

    switch (cmd) {
    case EWES_CMD_SO_PATH:
      if (p == NULL) {
	EWESerr(EWES_F_EWES_CTRL, ERR_R_PASSED_NULL_PARAMETER);
      } else if (initialised) {
	EWESerr(EWES_F_EWES_CTRL, EWES_R_ALREADY_LOADED);
      } else {
	WESENTROPY_LIBNAME = (const char *)p;
	to_return = 1;
      }
    default:
      EWESerr(EWES_F_EWES_CTRL, EWES_R_CTRL_COMMAND_NOT_IMPLEMENTED);
    }

    ewes_mutex_unlock(ewes_lockid);
    return to_return;
  }
  EWESerr(EWES_F_EWES_CTRL, EWES_R_LOCKING_ERROR);
  return 0;
}

/*
 * Functions to handle the mutexes
 */
static int ewes_mutex_init(int * lockid)
{
#ifdef EWES_DEBUG
  fprintf(stderr, "EWES lock: init\n");
#endif
  *lockid = CRYPTO_get_new_dynlockid();
  if (*lockid == 0)
    /* If the application hasn't registered any dynlock callbacks, let's
       assume it doesn't use threads */
    if (ERR_GET_REASON(ERR_peek_last_error()) == CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK) {
      ERR_clear_error();
    } else {
      *lockid = EWES_IMPOSSIBLE_LOCK_ID;
      return 0;               /* failure */
    }
  return 1;                   /* success */
}

static int ewes_mutex_lock(int lockid)
{
#ifdef EWES_DEBUG
  fprintf(stderr, "EWES lock: lock\n");
#endif
  if (lockid == EWES_IMPOSSIBLE_LOCK_ID)
    return 0;
  if (lockid)
    CRYPTO_w_lock(lockid);
  return 1;
}

static int ewes_mutex_unlock(int lockid)
{
#ifdef EWES_DEBUG
  fprintf(stderr, "EWES lock: unlock\n");
#endif
  if (lockid == EWES_IMPOSSIBLE_LOCK_ID)
    return 0;
  if (lockid)
    CRYPTO_w_unlock(lockid);
  return 1;
}

static int ewes_mutex_destroy(int * lockid)
{
#ifdef EWES_DEBUG
  fprintf(stderr, "EWES lock: destroy\n");
#endif
  if (lockid && *lockid < 0)
    CRYPTO_destroy_dynlockid(*lockid);
  *lockid = EWES_IMPOSSIBLE_LOCK_ID;
  return 1;
}

/* ------------------------------------------------------------ */
/*
 * RAND functions
 */

/* Random bytes */
static int ewes_rand_bytes(unsigned char *buf, int num)
{
  if (ewes_mutex_lock(ewes_lockid)) {
    int to_return = 0;		/* assume failure */
    tWesEngineError ret = WES_ENGINE_ERROR_NONE;
    unsigned long returned_bytes = 0;

    if (!ewes_context) {
      EWESerr(EWES_F_EWES_RAND_BYTES, EWES_R_NOT_INITIALISED);
      goto err;
    }

    ret = p_wesEngineGetBytes(ewes_context, buf, num, &returned_bytes);

    if (ret != WES_ENGINE_ERROR_NONE) {
      char error_buffer[1024];

      ret = p_wesEngineErrorStringGet(ret, error_buffer, sizeof(error_buffer));
      EWESerr(EWES_F_EWES_RAND_BYTES, EWES_R_REQUEST_FAILED);
      if (ret == WES_ENGINE_ERROR_NONE)
	ERR_add_error_data(1, error_buffer);
      goto err;
    }

    if (returned_bytes < num) {
      EWESerr(EWES_F_EWES_RAND_BYTES, EWES_R_RETURNED_LESS_BYTES);
      goto err;
    }

    to_return = 1;
  err:
    ewes_mutex_unlock(ewes_lockid);
    return to_return;
  }
  EWESerr(EWES_F_EWES_RAND_BYTES, EWES_R_LOCKING_ERROR);
  return 0;
}

/* Pseudo random bytes */
static int ewes_rand_pseudobytes(unsigned char *buf, int num)
{
  if (ewes_mutex_lock(ewes_lockid)) {
    int to_return = 0;		/* assume failure */
    tWesEngineError ret;
    unsigned long returned_bytes = 0;

    if (!ewes_context) {
      EWESerr(EWES_F_EWES_RAND_PSEUDOBYTES, EWES_R_NOT_INITIALISED);
      goto err;
    }

    ret = p_wesEngineGetPseudorandomBytes(ewes_context, buf, num, &returned_bytes);

    if (ret != WES_ENGINE_ERROR_NONE) {
      char error_buffer[1024];

      ret = p_wesEngineErrorStringGet(ret, error_buffer, sizeof(error_buffer));
      EWESerr(EWES_F_EWES_RAND_PSEUDOBYTES, EWES_R_REQUEST_FAILED);
      if (ret == WES_ENGINE_ERROR_NONE)
	ERR_add_error_data(1, error_buffer);
      goto err;
    }

    if (returned_bytes < num) {
      EWESerr(EWES_F_EWES_RAND_PSEUDOBYTES, EWES_R_RETURNED_LESS_BYTES);
      goto err;
    }

    to_return = 1;
  err:
    ewes_mutex_unlock(ewes_lockid);
    return to_return;
  }
  EWESerr(EWES_F_EWES_RAND_PSEUDOBYTES, EWES_R_LOCKING_ERROR);
  return 0;
}

static int ewes_rand_status(void)
{
  return ewes_context != 0;
}

