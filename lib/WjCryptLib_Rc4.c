////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  WjCryptLib_RC4
//
//  An implementation of RC4 stream cipher
//
//  This is free and unencumbered software released into the public domain - June 2013 waterjuice.org
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "WjCryptLib_Rc4.h"
#include <stdlib.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  INTERNAL FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define SwapBytes( Value1, Value2 )                 \
{                                                   \
    uint8_t temp = Value1;                          \
    Value1 = Value2;                                \
    Value2 = temp;                                  \
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Rc4Initialise
//
//  Initialises an RC4 cipher and discards the specified number of first bytes.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    Rc4Initialise
    (
        Rc4Context*     Context,        // [out]
        void const*     Key,            // [in]
        uint32_t        KeySize,        // [in]
        uint32_t        DropN           // [in]
    )
{
    uint32_t        i;
    uint32_t        j;
    uint32_t        n;

    // Setup key schedule
    for( i=0; i<256; i++ )
    {
        Context->S[i] = (uint8_t)i;
    }

    j = 0;
    for( i=0; i<256; i++ )
    {
        j = ( j + Context->S[i] + ((uint8_t*)Key)[i % KeySize] ) % 256;
        SwapBytes( Context->S[i], Context->S[j] );
    }

    i = 0;
    j = 0;

    // Drop first bytes (if requested)
    for( n=0; n<DropN; n++ )
    {
        i = ( i + 1 ) % 256;
        j = ( j + Context->S[i] ) % 256;
        SwapBytes( Context->S[i], Context->S[j] );
    }

    Context->i = i;
    Context->j = j;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Rc4Output
//
//  Outputs the requested number of bytes from the RC4 stream
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    Rc4Output
    (
        Rc4Context*     Context,        // [in out]
        void*           Buffer,         // [out]
        uint32_t        Size            // [in]
    )
{
    uint32_t    n;

    for( n=0; n<Size; n++ )
    {
        Context->i = ( Context->i + 1 ) % 256;
        Context->j = ( Context->j + Context->S[Context->i] ) % 256;
        SwapBytes( Context->S[Context->i], Context->S[Context->j] );

        ((uint8_t*)Buffer)[n] = Context->S[ (Context->S[Context->i] + Context->S[Context->j]) % 256 ];
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Rc4Xor
//
//  XORs the RC4 stream with an input buffer and puts the results in an output buffer. This is used for encrypting
//  and decrypting data. InBuffer and OutBuffer can point to the same location for inplace encrypting/decrypting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    Rc4Xor
    (
        Rc4Context*     Context,        // [in out]
        void const*     InBuffer,       // [in]
        void*           OutBuffer,      // [out]
        uint32_t        Size            // [in]
    )
{
    uint32_t    n;

    for( n=0; n<Size; n++ )
    {
        Context->i = ( Context->i + 1 ) % 256;
        Context->j = ( Context->j + Context->S[Context->i] ) % 256;
        SwapBytes( Context->S[Context->i], Context->S[Context->j] );

        ((uint8_t*)OutBuffer)[n] = ((uint8_t*)InBuffer)[n]
            ^ ( Context->S[ (Context->S[Context->i] + Context->S[Context->j]) % 256 ] );
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Rc4XorWithKey
//
//  This function combines Rc4Initialise and Rc4Xor. This is suitable when encrypting/decrypting data in one go with a
//  key that is not going to be reused.
//  InBuffer and OutBuffer can point to the same location for inplace encrypting/decrypting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    Rc4XorWithKey
    (
        uint8_t const*      Key,                    // [in]
        uint32_t            KeySize,                // [in]
        uint32_t            DropN,                  // [in]
        void const*         InBuffer,               // [in]
        void*               OutBuffer,              // [out]
        uint32_t            BufferSize              // [in]
    )
{
    Rc4Context      context;

    Rc4Initialise( &context, Key, KeySize, DropN );
    Rc4Xor( &context, InBuffer, OutBuffer, BufferSize );
}
