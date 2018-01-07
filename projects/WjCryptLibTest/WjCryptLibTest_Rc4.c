////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  WjCryptLibTest_Rc4
//
//  Tests the RC4 function against known test vectors to verify algorithms are correct.
//
//  This is free and unencumbered software released into the public domain - June 2013 waterjuice.org
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "WjCryptLib_Rc4.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TestRc4
//
//  Test RC4 algorithm against test vectors
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool
    TestRc4
    (
        void
    )
{
    struct
    {
        char        Key [100];
        uint32_t    Drop;
        uint8_t     Output [16];
    } TestVectors [] =
        {
            { "Key",    0,   {0xeb,0x9f,0x77,0x81,0xb7,0x34,0xca,0x72,0xa7,0x19,0x4a,0x28,0x67,0xb6,0x42,0x95} },
            { "Wiki",   0,   {0x60,0x44,0xdb,0x6d,0x41,0xb7,0xe8,0xe7,0xa4,0xd6,0xf9,0xfb,0xd4,0x42,0x83,0x54} },
            { "Secret", 0,   {0x04,0xd4,0x6b,0x05,0x3c,0xa8,0x7b,0x59,0x41,0x72,0x30,0x2a,0xec,0x9b,0xb9,0x92} },
            { "Key",    1,   {0x9f,0x77,0x81,0xb7,0x34,0xca,0x72,0xa7,0x19,0x4a,0x28,0x67,0xb6,0x42,0x95,0x0d} },
            { "Key",    256, {0x92,0xfd,0xd9,0xb6,0xe4,0x04,0xef,0x4f,0xa0,0x75,0xf1,0xa3,0x44,0xed,0x81,0x6b} },
        };

    Rc4Context      context;
    uint8_t         output [16];
    uint32_t        i;
    bool            success = true;

    for( i=0; i<(sizeof(TestVectors)/sizeof(TestVectors[0])); i++ )
    {
        Rc4Initialise( &context, TestVectors[i].Key, (uint8_t)strlen(TestVectors[i].Key), TestVectors[i].Drop );
        Rc4Output( &context, output, sizeof(output) );
        if( memcmp( output, TestVectors[i].Output, sizeof(output) ) != 0 )
        {
            printf( "TestRc4 - Failed test vector: %u\n", i );
            success = false;
        }
    }

    // Test by doing drop manually
    for( i=0; i<(sizeof(TestVectors)/sizeof(TestVectors[0])); i++ )
    {
        uint32_t x;

        Rc4Initialise( &context, TestVectors[i].Key, (uint8_t)strlen(TestVectors[i].Key), 0 );
        for( x=0; x<TestVectors[i].Drop; x++ )
        {
            Rc4Output( &context, output, 1 );
        }
        Rc4Output( &context, output, sizeof(output) );
        if( memcmp( output, TestVectors[i].Output, sizeof(output) ) != 0 )
        {
            printf( "TestRc4 - Failed test vector: %u [manual drop]\n", i );
            success = false;
        }
    }

    return success;
}
