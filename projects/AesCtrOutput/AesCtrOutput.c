////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesCtrOutput
//
//  Outputs bytes from an AES CTR stream. Key and IV are taken from command line. Bytes are output as hex
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
#include "WjCryptLib_AesCtr.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  DEFINITIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __min
   #define __min( x, y )  (((x) < (y))?(x):(y))
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  CONSTANTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define BUFFER_SIZE             1024

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  ReadHexData
//
//  Reads a string as hex and places it in Data. *pDataSize on entry specifies maximum number of bytes that can be
//  read, and on return is set to how many were read. This will be zero if it failed to read any.
//  This function ignores any character that isn't a hex character.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    ReadHexData
    (
        char const*         HexString,          // [in]
        uint8_t*            Data,               // [out]
        uint32_t*           pDataSize           // [in out]
    )
{
    uint32_t        i;
    char            holdingBuffer [3] = {0};
    uint32_t        holdingBufferIndex = 0;
    unsigned        hexToNumber;
    unsigned        outputIndex = 0;

    for( i=0; i<strlen(HexString); i++ )
    {
        if(     ( HexString[i] >= '0' && HexString[i] <= '9' )
            ||  ( HexString[i] >= 'A' && HexString[i] <= 'F' )
            ||  ( HexString[i] >= 'a' && HexString[i] <= 'f' ) )
        {
            holdingBuffer[holdingBufferIndex] = HexString[i];
            holdingBufferIndex += 1;

            if( 2 == holdingBufferIndex )
            {
                // Have two digits now so read it as a byte.
                sscanf( holdingBuffer, "%x", &hexToNumber );
                Data[outputIndex] = (uint8_t) hexToNumber;
                outputIndex += 1;
                if( outputIndex == *pDataSize )
                {
                    // No more space so stop reading
                    break;
                }
                holdingBufferIndex = 0;
            }
        }
    }

    *pDataSize = outputIndex;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  main
//
//  Program entry point
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int
    main
    (
        int             ArgC,
        char**          ArgV
    )
{
    uint32_t        numBytes;
    uint32_t        i;
    uint8_t         buffer [BUFFER_SIZE];
    uint32_t        amountLeft;
    uint32_t        chunk;
    AesCtrContext   aesCtr;
    uint8_t         key [AES_KEY_SIZE_256];
    uint32_t        keySize = sizeof(key);
    uint8_t         IV [AES_CTR_IV_SIZE];
    uint32_t        IVSize = sizeof(IV);

    if( 4 != ArgC )
    {
        printf(
            "Syntax\n"
            "   AesCtrOutput <Key> <IV> <NumBytes>\n"
            "     <Key> - 128, 192, or 256 bit written as hex\n"
            "     <IV>  - 64 bit written as hex\n"
            "     <NumBytes> - Number of bytes of stream to output\n" );
        return 1;
    }

    ReadHexData( ArgV[1], key, &keySize );
    if( AES_KEY_SIZE_128 != keySize && AES_KEY_SIZE_192 != keySize && AES_KEY_SIZE_256 != keySize )
    {
        printf( "Invalid key size. Must be 128, 192, or 256 bits\n" );
        return 1;
    }

    ReadHexData( ArgV[2], IV, &IVSize );
    if( AES_CTR_IV_SIZE != IVSize )
    {
        printf( "Invalid IV size. Must be 64 bits\n" );
        return 1;
    }

    numBytes = atoi( ArgV[3] );

    AesCtrInitialiseWithKey( &aesCtr, key, keySize, IV );

    amountLeft = numBytes;
    while( amountLeft > 0 )
    {
        chunk = __min( amountLeft, BUFFER_SIZE );
        AesCtrOutput( &aesCtr, buffer, chunk );
        amountLeft -= chunk;

        for( i=0; i<chunk; i++ )
        {
            printf( "%2.2x", buffer[i] );
        }
    }

    printf( "\n" );

    return 0;
}
