////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  WjCryptLibTest_AesCbc
//
//  Tests the cryptography functions against known test vectors to verify algorithms are correct.
//  Tests the following:
//     AES CBC
//
//  This is free and unencumbered software released into the public domain - March 2018 waterjuice.org
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "WjCryptLib_AesCbc.h"
#include "WjCryptLib_Sha1.h"
#include "WjCryptLib_Rc4.h"

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
// (Note: As CBC is not a stream cipher, the input is created using an RC4 stream generated from a key of 0)
// (Also note: openssl outputs an additional block of data due to some padding. We ignore this)
//   > dd if=/dev/zero iflag=count_bytes count=64 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-128-cbc -K 00000000000000000000000000000000 -iv 00000000000000000000000000000000 | head -c 64 | xxd -p -c 64
//   > dd if=/dev/zero iflag=count_bytes count=64 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-128-cbc -K 0102030405060708a1a2a3a4a5a6a7a8 -iv 00000000000000000000000000000000 | head -c 64 | xxd -p -c 64
//   > dd if=/dev/zero iflag=count_bytes count=64 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-128-cbc -K 00000000000000000000000000000000 -iv b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8 | head -c 64 | xxd -p -c 64
//   > dd if=/dev/zero iflag=count_bytes count=64 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-128-cbc -K 0102030405060708a1a2a3a4a5a6a7a8 -iv b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8 | head -c 64 | xxd -p -c 64
//   > dd if=/dev/zero iflag=count_bytes count=64 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-192-cbc -K 0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8 -iv c1c2c3c4c5c6c7c8d1d2d3d4d5d6d7d8 | head -c 64 | xxd -p -c 64
//   > dd if=/dev/zero iflag=count_bytes count=64 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-256-cbc -K 0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8 -iv d1d2d3d4d5d6d7d8e1e2e3e4e5e6e7e8 | head -c 64 | xxd -p -c 64
static TestVector gTestVectors [] =
{
    {
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "c2af41ffe8b9f1b295d68038e3e8ed3f70b72b168cd3d402ccbf0bb4fa12561fc703951c91d8ce81c5643155b5db1d34eb7b36c2cc4715c03ea24944bb5c5625"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8",
        "00000000000000000000000000000000",
        "638198794af111670d5d7a7e13851484f71831108a5a134a9329787ad73379eb449e5068150233c4f0ae8c08d86708bc09724efaad3e6936e03c58f83f2abf3f"
    },
    {
        "00000000000000000000000000000000",
        "b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8",
        "c696d1b757d5b4ee2069d1c50b1e5569aa931d0ecc058a5adce099e2f844153db0cf0884102720e42ab58efe449faba054edd92c4006fffbd9b0aec297b852ae"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8",
        "b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8",
        "a3c80c1c5ee817ad5faf31c6610e7895f480bdc9055362f0a7148b47b1dc5f11d041d94026266625cd6b512451a539ee9f3820667a84ace6cfbbe7edf746a14d"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8",
        "c1c2c3c4c5c6c7c8d1d2d3d4d5d6d7d8",
        "93928e29c82e5536bc5942c35bbbd4d7a69f0a7daa35c77ecb13b3ac2c46c473cb608f403982d8401385fd7fe66a1e329aa0f90a50180fb73b36e98cb7214736"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8",
        "d1d2d3d4d5d6d7d8e1e2e3e4e5e6e7e8",
        "2b559a644b62f1540c4ff9c50140fadedeefd49de9827dfbc8be8e4f7e2ac4ea746c8432d184059f62facaf765d90eadb7bdecac5e23bdc23f4026cd32d18ae2"
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
//  Tests AES CBC against fixed test vectors
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
    uint8_t         iv [AES_CBC_IV_SIZE];
    uint8_t         vector [TEST_VECTOR_OUTPUT_SIZE];
    uint8_t         aesCbcOutput [TEST_VECTOR_OUTPUT_SIZE];
    uint8_t         decryptBuffer [TEST_VECTOR_OUTPUT_SIZE];
    uint8_t         inputBuffer [TEST_VECTOR_OUTPUT_SIZE] = {0};
    uint8_t         rc4Key = 0;

    // We can't encrypt just a zero buffer or we will end up with same result as OFB. As this is not a stream
    // cipher we need to change the input. These test vectors were generated by using an RC4 stream as input.
    // The RC4 stream is created by using a key of 0.
    Rc4XorWithKey( &rc4Key, sizeof(rc4Key), 0, inputBuffer, inputBuffer, sizeof(inputBuffer) );

    for( vectorIndex=0; vectorIndex<NUM_TEST_VECTORS; vectorIndex++ )
    {
        HexToBytes( gTestVectors[vectorIndex].KeyHex,        key, &keySize );
        HexToBytes( gTestVectors[vectorIndex].IvHex,         iv, NULL );
        HexToBytes( gTestVectors[vectorIndex].CipherTextHex, vector, NULL );

        AesCbcEncryptWithKey( key, keySize, iv, inputBuffer, aesCbcOutput, TEST_VECTOR_OUTPUT_SIZE );
        if( 0 != memcmp( aesCbcOutput, vector, TEST_VECTOR_OUTPUT_SIZE ) )
        {
            printf( "Test vector (index:%u) failed\n", vectorIndex );
            return false;
        }

        AesCbcDecryptWithKey( key, keySize, iv, aesCbcOutput, decryptBuffer, TEST_VECTOR_OUTPUT_SIZE );
        if( 0 != memcmp( decryptBuffer, inputBuffer, TEST_VECTOR_OUTPUT_SIZE ) )
        {
            printf( "Test vector (index:%u) failed decrypt\n", vectorIndex );
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

//dd if=/dev/zero iflag=count_bytes count=1000000 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-128-cbc -K 00001111222233334444555566667777 -iv 88889999aaaabbbbccccddddeeeeffff | head -c 1000000 | openssl sha1
//(stdin)= 859463d3f0f27e67d37f05603f19b9d5c71c2059

    uint8_t const*  key = (uint8_t const*)"\x00\x00\x11\x11\x22\x22\x33\x33\x44\x44\x55\x55\x66\x66\x77\x77";
    uint8_t const*  iv = (uint8_t const*)"\x88\x88\x99\x99\xaa\xaa\xbb\xbb\xcc\xcc\xdd\xdd\xee\xee\xff\xff";
    uint8_t const*  sha1Hash = (uint8_t const*)"\x85\x94\x63\xd3\xf0\xf2\x7e\x67\xd3\x7f\x05\x60\x3f\x19\xb9\xd5\xc7\x1c\x20\x59";
    uint32_t const  numBytesToGenerate = 1000000;
    uint8_t const   rc4Key = 0;

    uint8_t*        buffer = malloc( numBytesToGenerate );
    uint8_t*        buffer2 = malloc( numBytesToGenerate );
    uint32_t        amountLeft = numBytesToGenerate;
    uint32_t        chunkSize;
    Sha1Context     sha1Context;
    AesCbcContext   aesCbcContext;
    SHA1_HASH       calcSha1;
    uint32_t        offset;
    SHA1_HASH       initialInputSha1;

    // Encrypt in one go first.
    // Generate the Rc4 stream to encrypt
    memset( buffer, 0, numBytesToGenerate );
    Rc4XorWithKey( &rc4Key, 1, 0, buffer, buffer, numBytesToGenerate );
    Sha1Calculate( buffer, numBytesToGenerate, &initialInputSha1 );

    AesCbcEncryptWithKey( key, AES_KEY_SIZE_128, iv, buffer, buffer2, numBytesToGenerate );

    Sha1Initialise( &sha1Context );
    Sha1Update( &sha1Context, buffer2, numBytesToGenerate );
    Sha1Finalise( &sha1Context, &calcSha1 );

    if( 0 != memcmp( &calcSha1, sha1Hash, SHA1_HASH_SIZE ) )
    {
        printf( "Large test vector failed (1)\n" );
        return false;
    }

    // Now decrypt the buffer to verify it goes back to the original.
    AesCbcDecryptWithKey( key, AES_KEY_SIZE_128, iv, buffer, buffer2, numBytesToGenerate );
    Sha1Calculate( buffer, numBytesToGenerate, &calcSha1 );

    if( 0 != memcmp( &calcSha1, &initialInputSha1, SHA1_HASH_SIZE ) )
    {
        printf( "Large test vector failed decrypting\n" );
        return false;
    }

    memset( buffer, 0, numBytesToGenerate );

    // Now encrypt in smaller pieces (10000 bytes at a time)
    Sha1Initialise( &sha1Context );
    AesCbcInitialiseWithKey( &aesCbcContext, key, AES_KEY_SIZE_128, iv );

    memset( buffer, 0, numBytesToGenerate );
    Rc4XorWithKey( &rc4Key, 1, 0, buffer, buffer, numBytesToGenerate );
    offset = 0;

    while( amountLeft > 0 )
    {
        chunkSize = MIN( amountLeft, 10000 );
        AesCbcEncrypt( &aesCbcContext, buffer+offset, buffer+offset, chunkSize );
        Sha1Update( &sha1Context, buffer+offset, chunkSize );
        amountLeft -= chunkSize;
        offset += chunkSize;
    }

    Sha1Finalise( &sha1Context, &calcSha1 );

    if( 0 != memcmp( &calcSha1, sha1Hash, SHA1_HASH_SIZE ) )
    {
        printf( "Large test vector failed (2)\n" );
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TestAesOfb
//
//  Test AES CBC algorithm
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool
    TestAesCbc
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

    return totalSuccess;
}
