////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  WjCryptLibTest_AesCtr
//
//  Tests the cryptography functions against known test vectors to verify algorithms are correct.
//  Tests the following:
//     AES CTR
//
//  This is free and unencumbered software released into the public domain - November 2017 waterjuice.org
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "WjCryptLib_AesCtr.h"
#include "WjCryptLib_Sha1.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  MACROS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define MIN( x, y ) ( ((x)<(y))?(x):(y) )

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TYPES
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define MAX_PLAINTEXT_SIZE      100

typedef struct
{
    char*           KeyHex;
    char*           IvHex;
    char*           CipherTextHex;
} TestVector;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  GLOBALS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// These test vectors were created using openssl. Using the following commands:
//   > openssl enc -aes-128-ctr -K 00000000000000000000000000000000 -iv 0000000000000000 -in zero.bin -out output0.bin
//   > openssl enc -aes-128-ctr -K 0102030405060708a1a2a3a4a5a6a7a8 -iv 0000000000000000 -in zero.bin -out output1.bin
//   > openssl enc -aes-128-ctr -K 00000000000000000000000000000000 -iv b1b2b3b4b5b6b7b8 -in zero.bin -out output2.bin
//   > openssl enc -aes-128-ctr -K 0102030405060708a1a2a3a4a5a6a7a8 -iv b1b2b3b4b5b6b7b8 -in zero.bin -out output3.bin
//   > openssl enc -aes-192-ctr -K 0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8 -iv c1c2c3c4c5c6c7c8 -in zero.bin -out output4.bin
//   > openssl enc -aes-256-ctr -K 0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8 -iv d1d2d3d4d5d6d7d8 -in zero.bin -out output5.bin
// Where zero.bin is a file containing 48 zero bytes.
static TestVector gTestVectors [] =
{
    {
        "00000000000000000000000000000000",
        "0000000000000000",
        "66e94bd4ef8a2c3b884cfa59ca342b2e58e2fccefa7e3061367f1d57a4e7455a0388dace60b6a392f328c2b971b2fe78"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8",
        "0000000000000000",
        "cdb33c236caa155b28d14e6db350537141fa2f4eafecf40a986f83229c7e74d30a981d4547b3c802ea215ed55a858a08"
    },
    {
        "00000000000000000000000000000000",
        "b1b2b3b4b5b6b7b8",
        "5ddcedba6a63f96e2b0429ee1a4459fc85e7e624ab33b89fdc4e88c034d483273568e033c96ad8a0bf5b420f4b43600d"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8",
        "b1b2b3b4b5b6b7b8",
        "7f1e34c4f33ee8dc162af7fbed6f317aa5806d244dd86557268be2296708ef7327aa4e5ed5780a3c070209ea2db04d79"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8",
        "c1c2c3c4c5c6c7c8",
        "8bd0847cad4f66dec6abeadcc85d1e0a62ab64931e16f1e8ccb6212c5cea3672c27d4cfd74b3e87ee2d787cc93f24496"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8",
        "d1d2d3d4d5d6d7d8",
        "1419da0fdac1f19ec0eb64af657201c672ab0df425d3faec3b67d70c86d5f780a222b63dbbc71ae7749417449dc39bfb"
    },
};

#define NUM_TEST_VECTORS ( sizeof(gTestVectors) / sizeof(gTestVectors[0]) )
#define TEST_VECTOR_OUTPUT_SIZE     48

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  INTERNAL FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  HexToBytes
//
//  Reads a string as hex and places it in Data. This function will output as many bytes as represented in the input
//  string, it will not check the output buffer length. On return *pDataSize will be number of bytes read.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    HexToBytes
    (
        char const*         HexString,              // [in]
        uint8_t*            Data,                   // [out]
        uint32_t*           pDataSize               // [out optional]
    )
{
    uint32_t        i;
    char            holdingBuffer [3] = {0};
    unsigned        hexToNumber;
    uint32_t        outputIndex = 0;

    for( i=0; i<strlen(HexString)/2; i++ )
    {
        holdingBuffer[0] = HexString[i*2 + 0];
        holdingBuffer[1] = HexString[i*2 + 1];
        sscanf( holdingBuffer, "%x", &hexToNumber );
        Data[i] = (uint8_t) hexToNumber;
        outputIndex += 1;
    }

    if( NULL != pDataSize )
    {
        *pDataSize = outputIndex;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TestVectors
//
//  Tests AES CTR against fixed test vectors
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
bool
    TestVectors
    (
        void
    )
{
    uint32_t        vectorIndex;
    uint8_t         key [AES_KEY_SIZE_256];
    uint32_t        keySize = 0;
    uint8_t         iv [AES_CTR_IV_SIZE];
    uint8_t         vector [TEST_VECTOR_OUTPUT_SIZE];
    uint8_t         aesCtrOutput [TEST_VECTOR_OUTPUT_SIZE];
    uint8_t const   zeroBuffer [TEST_VECTOR_OUTPUT_SIZE] = {0};

    for( vectorIndex=0; vectorIndex<NUM_TEST_VECTORS; vectorIndex++ )
    {
        HexToBytes( gTestVectors[vectorIndex].KeyHex,        key, &keySize );
        HexToBytes( gTestVectors[vectorIndex].IvHex,         iv, NULL );
        HexToBytes( gTestVectors[vectorIndex].CipherTextHex, vector, NULL );

        AesCtrXorWithKey( key, keySize, iv, zeroBuffer, aesCtrOutput, TEST_VECTOR_OUTPUT_SIZE );
        if( 0 != memcmp( aesCtrOutput, vector, TEST_VECTOR_OUTPUT_SIZE ) )
        {
            printf( "Test vector (index:%u) failed\n", vectorIndex );
            return false;
        }
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TestLargeVector
//
//  Tests AES CTR against a known large vector (of 1 million bytes). We check it against a known SHA-1 hash of
//  the output.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
bool
    TestLargeVector
    (
        void
    )
{

//dd if=/dev/zero iflag=count_bytes count=1000000 status=none | openssl enc -aes-128-ctr -K 00001111222233334444555566667777 -iv 88889999aaaabbbb | openssl sha1
//(stdin)= 6227c0192b110133fadd6d229790bbdf13c068ab

    uint8_t const*  key = (uint8_t const*)"\x00\x00\x11\x11\x22\x22\x33\x33\x44\x44\x55\x55\x66\x66\x77\x77";
    uint8_t const*  iv = (uint8_t const*)"\x88\x88\x99\x99\xaa\xaa\xbb\xbb";
    uint8_t const*  sha1Hash = (uint8_t const*)"\xe1\x63\x5f\xa4\xf5\x7c\x98\x54\xf6\x18\xec\x0c\x8f\x18\x7f\x04\x34\xa2\xe1\x72";
    uint32_t const  numBytesToGenerate = 1000000;

    uint8_t*        buffer = malloc( numBytesToGenerate );
    uint32_t        amountLeft = numBytesToGenerate;
    uint32_t        chunkSize;
    Sha1Context     sha1Context;
    AesCtrContext   aesCtrContext;
    SHA1_HASH       calcSha1;

    // Encrypt in one go first.
    memset( buffer, 0, numBytesToGenerate );
    AesCtrXorWithKey( key, AES_KEY_SIZE_128, iv, buffer, buffer, numBytesToGenerate );

    Sha1Initialise( &sha1Context );
    Sha1Update( &sha1Context, buffer, numBytesToGenerate );
    Sha1Finalise( &sha1Context, &calcSha1 );

    if( 0 != memcmp( &calcSha1, sha1Hash, SHA1_HASH_SIZE ) )
    {
        printf( "Large test vector failed\n" );
        return false;
    }

    memset( buffer, 0, numBytesToGenerate );

    // Now encrypt in smaller pieces (10000 bytes at a time)
    Sha1Initialise( &sha1Context );
    AesCtrInitialiseWithKey( &aesCtrContext, key, AES_KEY_SIZE_128, iv );

    while( amountLeft > 0 )
    {
        memset( buffer, 0, numBytesToGenerate );
        chunkSize = MIN( amountLeft, 10000 );
        AesCtrOutput( &aesCtrContext, buffer, chunkSize );
        Sha1Update( &sha1Context, buffer, chunkSize );
        amountLeft -= chunkSize;
    }

    Sha1Finalise( &sha1Context, &calcSha1 );

    if( 0 != memcmp( &calcSha1, sha1Hash, SHA1_HASH_SIZE ) )
    {
        printf( "Large test vector failed\n" );
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TestStreamConsistency
//
//  Tests that an AES CTR stream is consistent regardless of the chunk sizes of the requests and/or stream
//  repositioning.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
bool
    TestStreamConsistency
    (
        void
    )
{
    bool            success = true;
    uint8_t const   key[AES_KEY_SIZE_128] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
    uint8_t const   iv[AES_CTR_IV_SIZE] = { 1,2,3,4,5,6,7,8 };
    #define STREAMSIZE 1000
    uint8_t         stream [STREAMSIZE];
    uint8_t         newStream [STREAMSIZE];
    uint8_t const   zeroStream [STREAMSIZE] = {0};
    AesCtrContext   context;
    uint32_t        chunkSize;

    // First fill in stream with 1000 bytes generated in one go.
    memset( stream, 0, STREAMSIZE );
    AesCtrXorWithKey( key, sizeof(key), iv, stream, stream, STREAMSIZE );

    // Perform sanity check that the key is not all zero!
    if( 0 == memcmp( stream, zeroStream, STREAMSIZE ) )
    {
        printf( "AES CTR Stream all zero\n" );
        success = false;
        return success;
    }

    // Now recreate the stream in small bits. Starting at 1 byte at a time and increasing chunk size
    AesCtrInitialiseWithKey( &context, key, sizeof(key), iv );
    for( chunkSize=1; chunkSize<64; chunkSize++ )
    {
        uint32_t amountLeft = STREAMSIZE;
        uint32_t offset = 0;
        memset( newStream, 0, STREAMSIZE );

        while( amountLeft > 0 )
        {
            uint32_t thisChunkSize = MIN( chunkSize, amountLeft );

            // Set stream position to +8 where it currently is, this will mean half the time it will have to
            // reset the internal block. We are going to ignore this position and bring it back straight away,
            // we just want to verify that it can handle being moved around.
            AesCtrSetStreamIndex( &context, offset+8 );

            // Set stream pointer to correct place and output the chunk
            AesCtrSetStreamIndex( &context, offset );
            AesCtrOutput( &context, newStream+offset, thisChunkSize );

            offset += thisChunkSize;
            amountLeft -= thisChunkSize;
        }

        // Now verify that the stream is consistent with the one generated all at once.
        if( 0 != memcmp( stream, newStream, STREAMSIZE ) )
        {
            printf( "AES CTR Stream not consistent\n" );
            success = false;
            break;
        }
    }

    #undef STREAMSIZE

    return success;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TestEndianCorrectness
//
//  Verifies that endianess is handled correctly. This will force the internal block counter to be a large number
//  that uses multiple bytes, and then checks the final output.
//  This should return correctly regardless of big or little endian processor.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
bool
    TestEndianCorrectness
    (
        void
    )
{
    AesCtrContext   context;
    uint8_t const   key [AES_KEY_SIZE_128] = { 1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4 };
    uint8_t const   iv [AES_CTR_IV_SIZE] = { 5,5,5,5,6,6,6,6 };
    uint64_t const  positionIndex = 0x1020304050607080ULL;
    uint8_t         output [256 / 8] = {0};
    uint8_t const   vector [256 / 8] =
        { 0x17, 0x07, 0x27, 0x7b, 0x9e, 0x51, 0xdf, 0x5b,
          0x23, 0xbe, 0xa1, 0xce, 0xc9, 0x40, 0x49, 0xfc,
          0xf8, 0x8f, 0x45, 0xd1, 0xf6, 0x68, 0x28, 0x54,
          0x6f, 0xef, 0xce, 0xf9, 0x23, 0x1b, 0xb0, 0x08 };

    AesCtrInitialiseWithKey( &context, key, sizeof(key), iv );
    AesCtrSetStreamIndex( &context, positionIndex );
    AesCtrOutput( &context, output, sizeof(output) );

    if( 0 != memcmp( vector, output, sizeof(vector) ) )
    {
        printf( "Fail on endianness test\n" );
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TestAesCtr
//
//  Test AES CTR algorithm
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool
    TestAesCtr
    (
        void
    )
{
    bool        totalSuccess = true;
    bool        success;

    success = TestVectors( );
    if( !success ) { totalSuccess = false; }

    success = TestLargeVector( );
    if( !success ) { totalSuccess = false; }

    success = TestStreamConsistency( );
    if( !success ) { totalSuccess = false; }

    success = TestEndianCorrectness( );
    if( !success ) { totalSuccess = false; }

    return totalSuccess;
}
