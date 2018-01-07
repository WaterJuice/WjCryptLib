////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  WjCryptLibTest_AesOfb
//
//  Tests the cryptography functions against known test vectors to verify algorithms are correct.
//  Tests the following:
//     AES OFB
//
//  This is free and unencumbered software released into the public domain - January 2018 waterjuice.org
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "WjCryptLib_AesOfb.h"
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
//   > dd if=/dev/zero iflag=count_bytes count=48 status=none | openssl enc -aes-128-ofb -K 00000000000000000000000000000000 -iv 00000000000000000000000000000000 | xxd -p -c 48
//   > dd if=/dev/zero iflag=count_bytes count=48 status=none | openssl enc -aes-128-ofb -K 0102030405060708a1a2a3a4a5a6a7a8 -iv 00000000000000000000000000000000 | xxd -p -c 48
//   > dd if=/dev/zero iflag=count_bytes count=48 status=none | openssl enc -aes-128-ofb -K 00000000000000000000000000000000 -iv b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8 | xxd -p -c 48
//   > dd if=/dev/zero iflag=count_bytes count=48 status=none | openssl enc -aes-128-ofb -K 0102030405060708a1a2a3a4a5a6a7a8 -iv b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8 | xxd -p -c 48
//   > dd if=/dev/zero iflag=count_bytes count=48 status=none | openssl enc -aes-192-ofb -K 0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8 -iv c1c2c3c4c5c6c7c8d1d2d3d4d5d6d7d8 | xxd -p -c 48
//   > dd if=/dev/zero iflag=count_bytes count=48 status=none | openssl enc -aes-256-ofb -K 0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8 -iv d1d2d3d4d5d6d7d8e1e2e3e4e5e6e7e8 | xxd -p -c 48
static TestVector gTestVectors [] =
{
    {
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "66e94bd4ef8a2c3b884cfa59ca342b2ef795bd4a52e29ed713d313fa20e98dbca10cf66d0fddf3405370b4bf8df5bfb3"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8",
        "00000000000000000000000000000000",
        "cdb33c236caa155b28d14e6db35053718a906fc0050ae8ad054621e487e5b0a264873309a9471152104a0a51361a91af"
    },
    {
        "00000000000000000000000000000000",
        "b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8",
        "93fc4d6374dc544d40181d39066e9b0077aa627a84dbd57c9e72a1bbbc8bd1e082faf44d5ce57f6320e9f33d38a3a268"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8",
        "b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8",
        "551eb0c4d89d7e1b537b30f627cc5a0afdebd5a07483107df8555dbae9453189ae13766c9678554971151486cee958af"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8",
        "c1c2c3c4c5c6c7c8d1d2d3d4d5d6d7d8",
        "e9128df92fd1da443f826d84fd46be40fffb4ad23477a02efb14cbfd9a28ebcc2e6a5948cd1980e7cd6f5d386f7f6539"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8",
        "d1d2d3d4d5d6d7d8e1e2e3e4e5e6e7e8",
        "06a9a20023d47df78a5ead97715a85921cab7d5114fb74a1b99e66d915a0e125a0fcf198d93364235f9a33c02dc170f6"
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
//  Tests AES OFB against fixed test vectors
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
    uint8_t         iv [AES_OFB_IV_SIZE];
    uint8_t         vector [TEST_VECTOR_OUTPUT_SIZE];
    uint8_t         aesOfbOutput [TEST_VECTOR_OUTPUT_SIZE];
    uint8_t const   zeroBuffer [TEST_VECTOR_OUTPUT_SIZE] = {0};

    for( vectorIndex=0; vectorIndex<NUM_TEST_VECTORS; vectorIndex++ )
    {
        HexToBytes( gTestVectors[vectorIndex].KeyHex,        key, &keySize );
        HexToBytes( gTestVectors[vectorIndex].IvHex,         iv, NULL );
        HexToBytes( gTestVectors[vectorIndex].CipherTextHex, vector, NULL );

        AesOfbXorWithKey( key, keySize, iv, zeroBuffer, aesOfbOutput, TEST_VECTOR_OUTPUT_SIZE );
        if( 0 != memcmp( aesOfbOutput, vector, TEST_VECTOR_OUTPUT_SIZE ) )
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
//  Tests AES OFB against a known large vector (of 1 million bytes). We check it against a known SHA-1 hash of
//  the output.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
bool
    TestLargeVector
    (
        void
    )
{

//dd if=/dev/zero iflag=count_bytes count=1000000 status=none | openssl enc -aes-128-ofb -K 00001111222233334444555566667777 -iv 88889999aaaabbbbccccddddeeeeffff | openssl sha1
//(stdin)= a0824dca21938b33a5a8db26c8ab2428624db6d3

    uint8_t const*  key = (uint8_t const*)"\x00\x00\x11\x11\x22\x22\x33\x33\x44\x44\x55\x55\x66\x66\x77\x77";
    uint8_t const*  iv = (uint8_t const*)"\x88\x88\x99\x99\xaa\xaa\xbb\xbb\xcc\xcc\xdd\xdd\xee\xee\xff\xff";
    uint8_t const*  sha1Hash = (uint8_t const*)"\xa0\x82\x4d\xca\x21\x93\x8b\x33\xa5\xa8\xdb\x26\xc8\xab\x24\x28\x62\x4d\xb6\xd3";
    uint32_t const  numBytesToGenerate = 1000000;

    uint8_t*        buffer = malloc( numBytesToGenerate );
    uint32_t        amountLeft = numBytesToGenerate;
    uint32_t        chunkSize;
    Sha1Context     sha1Context;
    AesOfbContext   aesOfbContext;
    SHA1_HASH       calcSha1;

    // Encrypt in one go first.
    memset( buffer, 0, numBytesToGenerate );
    AesOfbXorWithKey( key, AES_KEY_SIZE_128, iv, buffer, buffer, numBytesToGenerate );

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
    AesOfbInitialiseWithKey( &aesOfbContext, key, AES_KEY_SIZE_128, iv );

    while( amountLeft > 0 )
    {
        memset( buffer, 0, numBytesToGenerate );
        chunkSize = MIN( amountLeft, 10000 );
        AesOfbOutput( &aesOfbContext, buffer, chunkSize );
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
//  Tests that an AES OFB stream is consistent regardless of the chunk sizes of the requests and/or stream
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
    uint8_t const   iv[AES_OFB_IV_SIZE] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
    #define STREAMSIZE 1000
    uint8_t         stream [STREAMSIZE];
    uint8_t         newStream [STREAMSIZE];
    uint8_t const   zeroStream [STREAMSIZE] = {0};
    AesOfbContext   context;
    uint32_t        chunkSize;

    // First fill in stream with 1000 bytes generated in one go.
    memset( stream, 0, STREAMSIZE );
    AesOfbXorWithKey( key, sizeof(key), iv, stream, stream, STREAMSIZE );

    // Perform sanity check that the key is not all zero!
    if( 0 == memcmp( stream, zeroStream, STREAMSIZE ) )
    {
        printf( "AES OFB Stream all zero\n" );
        success = false;
        return success;
    }

    // Now recreate the stream in small bits. Starting at 1 byte at a time and increasing chunk size
    for( chunkSize=1; chunkSize<64; chunkSize++ )
    {
        uint32_t amountLeft = STREAMSIZE;
        uint32_t offset = 0;
        memset( newStream, 0, STREAMSIZE );

        AesOfbInitialiseWithKey( &context, key, sizeof(key), iv );

        while( amountLeft > 0 )
        {
            uint32_t thisChunkSize = MIN( chunkSize, amountLeft );

            AesOfbOutput( &context, newStream+offset, thisChunkSize );

            offset += thisChunkSize;
            amountLeft -= thisChunkSize;
        }

        // Now verify that the stream is consistent with the one generated all at once.
        if( 0 != memcmp( stream, newStream, STREAMSIZE ) )
        {
            printf( "AES OFB Stream not consistent\n" );
            success = false;
            break;
        }
    }

    #undef STREAMSIZE

    return success;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TestAesOfb
//
//  Test AES OFB algorithm
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool
    TestAesOfb
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

    return totalSuccess;
}
