////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  WjCryptLib_AesOfb
//
//  Implementation of AES OFB stream cipher.
//
//  Depends on: CryptoLib_Aes
//
//  AES OFB is a stream cipher using the AES block cipher in output feedback mode.
//  This implementation works on both little and big endian architectures.
//
//  This is free and unencumbered software released into the public domain - January 2018 waterjuice.org
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "WjCryptLib_AesOfb.h"
#include "WjCryptLib_Aes.h"
#include <stdint.h>
#include <memory.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  MACROS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define MIN( x, y ) ( ((x)<(y))?(x):(y) )

#define STORE64H( x, y )                                                       \
   { (y)[0] = (uint8_t)(((x)>>56)&255); (y)[1] = (uint8_t)(((x)>>48)&255);     \
     (y)[2] = (uint8_t)(((x)>>40)&255); (y)[3] = (uint8_t)(((x)>>32)&255);     \
     (y)[4] = (uint8_t)(((x)>>24)&255); (y)[5] = (uint8_t)(((x)>>16)&255);     \
     (y)[6] = (uint8_t)(((x)>>8)&255);  (y)[7] = (uint8_t)((x)&255); }

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  INTERNAL FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  XorBuffer
//
//  Takes two Source buffers and XORs them together and puts the result in DestinationBuffer
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    XorBuffers
    (
        uint8_t const*      SourceBuffer1,          // [in]
        uint8_t const*      SourceBuffer2,          // [in]
        uint8_t*            DestinationBuffer,      // [out]
        uint32_t            Amount                  // [in]
    )
{
    uint32_t    i;

    for( i=0; i<Amount; i++ )
    {
        DestinationBuffer[i] = SourceBuffer1[i] ^ SourceBuffer2[i];
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesOfbInitialise
//
//  Initialises an AesOfbContext with an already initialised AesContext and a IV. This function can quickly be used
//  to change the IV without requiring the more lengthy processes of reinitialising an AES key.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesOfbInitialise
    (
        AesOfbContext*      Context,                // [out]
        AesContext const*   InitialisedAesContext,  // [in]
        uint8_t const       IV [AES_OFB_IV_SIZE]    // [in]
    )
{
    // Setup context values
    Context->Aes = *InitialisedAesContext;
    memcpy( Context->CurrentCipherBlock, IV, sizeof(Context->CurrentCipherBlock) );
    Context->IndexWithinCipherBlock = 0;

    // Generate the first cipher block of the stream.
    AesEncryptInPlace( &Context->Aes, Context->CurrentCipherBlock );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesOfbInitialiseWithKey
//
//  Initialises an AesOfbContext with an AES Key and an IV. This combines the initialising an AES Context and then
//  running AesOfbInitialise. KeySize must be 16, 24, or 32 (for 128, 192, or 256 bit key size)
//  Returns 0 if successful, or -1 if invalid KeySize provided
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int
    AesOfbInitialiseWithKey
    (
        AesOfbContext*      Context,                // [out]
        uint8_t const*      Key,                    // [in]
        uint32_t            KeySize,                // [in]
        uint8_t const       IV [AES_OFB_IV_SIZE]    // [in]
    )
{
    AesContext aes;

    // Initialise AES Context
    if( 0 != AesInitialise( &aes, Key, KeySize ) )
    {
        return -1;
    }

    // Now set-up AesOfbContext
    AesOfbInitialise( Context, &aes, IV );
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesOfbXor
//
//  XORs the stream of byte of the AesOfbContext from its current stream position onto the specified buffer. This will
//  advance the stream index by that number of bytes.
//  Use once over data to encrypt it. Use it a second time over the same data from the same stream position and the
//  data will be decrypted.
//  InBuffer and OutBuffer can point to the same location for in-place encrypting/decrypting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesOfbXor
    (
        AesOfbContext*      Context,                // [in out]
        void const*         InBuffer,               // [in]
        void*               OutBuffer,              // [out]
        uint32_t            Size                    // [in]
    )
{
    uint32_t    amountLeft = Size;
    uint32_t    outputOffset = 0;
    uint32_t    chunkSize;
    uint32_t    amountAvailableInBlock;

    // First determine how much is available in the current block.
    amountAvailableInBlock = AES_BLOCK_SIZE - Context->IndexWithinCipherBlock;

    // Determine how much of the current block we will take, either all that is available, or less
    // if the amount requested is smaller.
    chunkSize = MIN( amountAvailableInBlock, amountLeft );

    // XOR the bytes from the cipher block
    XorBuffers( InBuffer, Context->CurrentCipherBlock + (AES_BLOCK_SIZE - amountAvailableInBlock), OutBuffer, chunkSize );

    amountLeft -= chunkSize;
    outputOffset += chunkSize;
    Context->IndexWithinCipherBlock += chunkSize;

    // Now start generating new cipher blocks as required.
    while( amountLeft > 0 )
    {
        // Generate new cipher block
        AesEncryptInPlace( &Context->Aes, Context->CurrentCipherBlock );

        // Determine how much of the current block we need and XOR it out onto the buffer
        chunkSize = MIN( amountLeft, AES_BLOCK_SIZE );
        XorBuffers( (uint8_t*)InBuffer + outputOffset, Context->CurrentCipherBlock, (uint8_t*)OutBuffer + outputOffset, chunkSize );

        amountLeft -= chunkSize;
        outputOffset += chunkSize;
        Context->IndexWithinCipherBlock = chunkSize;    // Note: Not incremented
    }

    // If we ended up completely reading the last cipher block we need to generate a new one for next time.
    if( AES_BLOCK_SIZE == chunkSize )
    {
        AesEncryptInPlace( &Context->Aes, Context->CurrentCipherBlock );
        Context->IndexWithinCipherBlock = 0;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesOfbOutput
//
//  Outputs the stream of byte of the AesOfbContext from its current stream position. This will advance the stream
//  index by that number of bytes.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesOfbOutput
    (
        AesOfbContext*      Context,                // [in out]
        void*               Buffer,                 // [out]
        uint32_t            Size                    // [in]
    )
{
    memset( Buffer, 0, Size );
    AesOfbXor( Context, Buffer, Buffer, Size );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesOfbXorWithKey
//
//  This function combines AesOfbInitialiseWithKey and AesOfbXor. This is suitable when encrypting/decypting data in
//  one go with a key that is not going to be reused.
//  This will used the provided Key and IV and generate a stream that is XORed over Buffer.
//  InBuffer and OutBuffer can point to the same location for inplace encrypting/decrypting
//  Returns 0 if successful, or -1 if invalid KeySize provided
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int
    AesOfbXorWithKey
    (
        uint8_t const*      Key,                    // [in]
        uint32_t            KeySize,                // [in]
        uint8_t const       IV [AES_OFB_IV_SIZE],   // [in]
        void const*         InBuffer,               // [in]
        void*               OutBuffer,              // [out]
        uint32_t            BufferSize              // [in]
    )
{
    int             error;
    AesOfbContext   context;

    error = AesOfbInitialiseWithKey( &context, Key, KeySize, IV );
    if( 0 == error )
    {
        AesOfbXor( &context, InBuffer, OutBuffer, BufferSize );
    }

    return error;
}
