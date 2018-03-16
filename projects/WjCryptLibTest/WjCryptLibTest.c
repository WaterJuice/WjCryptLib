////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  WjCryptLibTest
//
//  Tests the cryptography functions against known test vectors to verify algorithms are correct.
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
#include "WjCryptLibTest_Aes.h"
#include "WjCryptLibTest_AesCbc.h"
#include "WjCryptLibTest_AesCtr.h"
#include "WjCryptLibTest_AesOfb.h"
#include "WjCryptLibTest_Hashes.h"
#include "WjCryptLibTest_Rc4.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  main
//
//  Program entry point
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int
    main
    (
        void
    )
{
    bool    success;
    bool    allSuccess = true;

    printf(
        "WjCryptLibTest\n"
        "------------\n"
        "\n" );

    success = TestHashes( );
    if( !success ) { allSuccess = false; }

    success = TestRc4( );
    if( !success ) { allSuccess = false; }
    printf( "Test RC4     - %s\n", success?"Pass":"Fail" );

    success = TestAes( );
    if( !success ) { allSuccess = false; }
    printf( "Test AES     - %s\n", success?"Pass":"Fail" );

    success = TestAesCbc( );
    if( !success ) { allSuccess = false; }
    printf( "Test AES CBC - %s\n", success?"Pass":"Fail" );

    success = TestAesCtr( );
    if( !success ) { allSuccess = false; }
    printf( "Test AES CTR - %s\n", success?"Pass":"Fail" );

    success = TestAesOfb( );
    if( !success ) { allSuccess = false; }
    printf( "Test AES OFB - %s\n", success?"Pass":"Fail" );

    printf( "\n" );
    if( allSuccess )
    {
        printf( "All tests passed.\n" );
    }
    else
    {
        printf( "Fail.\n" );
        return 1;
    }

    return 0;
}
