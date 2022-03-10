////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  WjCryptLib_Sha512
//
//  Implementation of SHA512 hash function.
//  Original author: Tom St Denis, tomstdenis@gmail.com, http://libtom.org
//  Modified by WaterJuice retaining Public Domain license.
//
//  This is free and unencumbered software released into the public domain - June 2013 waterjuice.org
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma once

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    uint64_t    length;
    uint64_t    state[8];
    uint32_t    curlen;
    uint8_t     buf[128];
} Sha512Context;

#define SHA512_HASH_SIZE           ( 512 / 8 )

typedef struct
{
    uint8_t      bytes [SHA512_HASH_SIZE];
} SHA512_HASH;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Sha512Initialise
//
//  Initialises a SHA512 Context. Use this to initialise/reset a context.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    Sha512Initialise
    (
        Sha512Context*      Context         // [out]
    );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Sha512Update
//
//  Adds data to the SHA512 context. This will process the data and update the internal state of the context. Keep on
//  calling this function until all the data has been added. Then call Sha512Finalise to calculate the hash.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    Sha512Update
    (
        Sha512Context*      Context,        // [in out]
        void const*         Buffer,         // [in]
        uint32_t            BufferSize      // [in]
    );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Sha512Finalise
//
//  Performs the final calculation of the hash and returns the digest (64 byte buffer containing 512bit hash). After
//  calling this, Sha512Initialised must be used to reuse the context.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    Sha512Finalise
    (
        Sha512Context*      Context,        // [in out]
        SHA512_HASH*        Digest          // [out]
    );

#ifdef __cplusplus
}
#endif
