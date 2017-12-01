////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  CryptLib_AesCtr
//
//  Implementation of AES CTR stream cipher.
//
//  Depends on: CryptoLib_Aes
//
//  AES CTR is a stream cipher using the AES block cipher in counter mode.
//  This implementation works on both little and big endian architectures.
//
//  This is free and unencumbered software released into the public domain - November 2017 waterjuice.org
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "CryptLib_AesCtr.h"
#include "CryptLib_Aes.h"
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
//  CreateCurrentCipherBlock
//
//  Takes the IV and the counter in the AesCtrContext and produces the cipher block (CurrentCipherBlock). The cipher
//  block is produced by first creating a 128 bit block with the IV as first 64 bits and the CurrentCipherBlockIndex
//  stored as the remaining 64bits in Network byte order (Big Endian)
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    CreateCurrentCipherBlock
    (
        AesCtrContext*      Context                 // [in out]
    )
{
    // Build block by first copying in the IV
    memcpy( Context->CurrentCipherBlock, Context->IV, AES_CTR_IV_SIZE );

    // Now place in the counter in Big Endian form
    STORE64H( Context->CurrentCipherBlockIndex, Context->CurrentCipherBlock + AES_CTR_IV_SIZE );

    // Perform AES encryption on the block
    AesEncryptInPlace( &Context->Aes, Context->CurrentCipherBlock );
}

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
//  AesCtrInitialise
//
//  Initialises an AesCtrContext with an already initialised AesContext and a IV. This function can quickly be used
//  to change the IV without requiring the more length processes of reinitialising an AES key.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesCtrInitialise
    (
        AesContext const*   InitialisedAesContext,  // [in]
        uint8_t const       IV [AES_CTR_IV_SIZE],   // [in]
        AesCtrContext*      Context                 // [out]
    )
{
    // Setup context values
    Context->Aes = *InitialisedAesContext;
    memcpy( Context->IV, IV, AES_CTR_IV_SIZE );
    Context->StreamIndex = 0;
    Context->CurrentCipherBlockIndex = 0;

    // Generate the first cipher block of the stream.
    CreateCurrentCipherBlock( Context );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesCtrInitialiseWithKey
//
//  Initialises an AesCtrContext with an AES Key and an IV. This combines the initialising an AES Context and then
//  running AesCtrInitialise. KeySize must be 16, 24, or 32 (for 128, 192, or 256 bit key size)
//  Returns 0 if successful, or -1 if invalid KeySize provided
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int
    AesCtrInitialiseWithKey
    (
        uint8_t const*      Key,                    // [in]
        uint32_t            KeySize,                // [in]
        uint8_t const       IV [AES_CTR_IV_SIZE],   // [in]
        AesCtrContext*      Context                 // [out]
    )
{
    AesContext aes;

    // Initialise AES Context
    switch( KeySize )
    {
    case AES_KEY_SIZE_128: AesInitialise128( Key, &aes ); break;
    case AES_KEY_SIZE_192: AesInitialise192( Key, &aes ); break;
    case AES_KEY_SIZE_256: AesInitialise256( Key, &aes ); break;
    default:
        // Invalid key size
        return -1;
    }

    // Now set-up AesCtrContext
    AesCtrInitialise( &aes, IV, Context );
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesCtrSetStreamIndex
//
//  Sets the current stream index to any arbitrary position. Setting to 0 sets it to the beginning of the stream. Any
//  subsequent output will start from this position
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesCtrSetStreamIndex
    (
        AesCtrContext*      Context,                // [in out]
        uint64_t            StreamIndex             // [in]
    )
{
    uint64_t    blockIndex = StreamIndex / AES_BLOCK_SIZE;

    Context->StreamIndex = StreamIndex;
    if( blockIndex != Context->CurrentCipherBlockIndex )
    {
        // Update block index and generate new cipher block as the new StreamIndex is inside a different block to the
        // one we currently had.
        Context->CurrentCipherBlockIndex = blockIndex;
        CreateCurrentCipherBlock( Context );
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesCtrXor
//
//  XORs the stream of byte of the AesCtrContext from its current stream position onto the specified buffer. This will
//  advance the stream index by that number of bytes.
//  Use once over data to encrypt it. Use it a second time over the same data from the same stream position and the
//  data will be decrypted.
//  InBuffer and OutBuffer can point to the same location for inplace encrypting/decrypting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesCtrXor
    (
        AesCtrContext*      Context,                // [in out]
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
    amountAvailableInBlock = AES_BLOCK_SIZE - (Context->StreamIndex % AES_BLOCK_SIZE);

    // Determine how much of the current block we will take, either all that is available, or less
    // if the amount requested is smaller.
    chunkSize = MIN( amountAvailableInBlock, amountLeft );

    // XOR the bytes from the cipher block
    XorBuffers( InBuffer, Context->CurrentCipherBlock + (AES_BLOCK_SIZE - amountAvailableInBlock), OutBuffer, chunkSize );

    amountLeft -= chunkSize;
    outputOffset += chunkSize;

    // Now start generating new cipher blocks as required.
    while( amountLeft > 0 )
    {
        // Increment block index and regenerate cipher block
        Context->CurrentCipherBlockIndex += 1;
        CreateCurrentCipherBlock( Context );

        // Determine how much of the current block we need and XOR it out onto the buffer
        chunkSize = MIN( amountLeft, AES_BLOCK_SIZE );
        XorBuffers( (uint8_t*)InBuffer + outputOffset, Context->CurrentCipherBlock, (uint8_t*)OutBuffer + outputOffset, chunkSize );

        amountLeft -= chunkSize;
        outputOffset += chunkSize;
    }

    // All data read out now, so update index in the context.
    Context->StreamIndex += Size;

    // If we ended up completely reading the last cipher block we need to generate a new one for next time.
    if( AES_BLOCK_SIZE == chunkSize )
    {
        Context->CurrentCipherBlockIndex += 1;
        CreateCurrentCipherBlock( Context );
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesCtrOutput
//
//  Outputs the stream of byte of the AesCtrContext from its current stream position. This will advance the stream
//  index by that number of bytes.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesCtrOutput
    (
        AesCtrContext*      Context,                // [in out]
        void*               Buffer,                 // [out]
        uint32_t            Size                    // [in]
    )
{
    memset( Buffer, 0, Size );
    AesCtrXor( Context, Buffer, Buffer, Size );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesCtrXorWithKey
//
//  This function combines AesCtrInitialiseWithKey and AesCtrXor. This is suitable when encrypting/decypting data in
//  one go with a key that is not going to be reused.
//  This will used the provided Key and IV and generate a stream that is XORed over Buffer.
//  InBuffer and OutBuffer can point to the same location for inplace encrypting/decrypting
//  Returns 0 if successful, or -1 if invalid KeySize provided
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int
    AesCtrXorWithKey
    (
        uint8_t const*      Key,                    // [in]
        uint32_t            KeySize,                // [in]
        uint8_t const       IV [AES_CTR_IV_SIZE],   // [in]
        void const*         InBuffer,               // [in]
        void*               OutBuffer,              // [out]
        uint32_t            BufferSize              // [in]
    )
{
    int             error;
    AesCtrContext   context;

    error = AesCtrInitialiseWithKey( Key, KeySize, IV, &context );
    if( 0 == error )
    {
        AesCtrXor( &context, InBuffer, OutBuffer, BufferSize );
    }

    return error;
}
