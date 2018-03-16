////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesBlock
//
//  Encrypts or Decrypts a single 128 bit block specified on the command line as a hex string. Key is also on
//  command line and may be 128, 192, or 256 bits in size.
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
#include "WjCryptLib_Aes.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  DEFINES
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifdef _MSC_VER
    #define StringCaseInsensitiveCmp    stricmp
#else
    #define StringCaseInsensitiveCmp    strcasecmp
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  INTERNAL FUNCTIONS
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
        char const*         HexString,
        uint8_t*            Data,
        uint32_t*           pDataSize
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
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
    uint8_t         block [128 / 8] = {0};
    uint32_t        blockSize = sizeof( block );
    uint8_t         key [256 / 8] = {0};
    uint32_t        keySize = sizeof( key );
    uint8_t*        bufferPtr;
    uint32_t*       bufferSizePtr;
    uint32_t        i;
    uint32_t        paramIndex = 0;
    bool            decryptMode = false;
    AesContext      aesContext;

    if( 4 != ArgC && 3 != ArgC )
    {
        printf(
            "Syntax\n"
            "   AesBlock [-D] <KeyHex> <BlockHex>\n" );
        return 1;
    }

    for( i=1; i<(uint32_t)ArgC; i++ )
    {
        if( 0 == StringCaseInsensitiveCmp( ArgV[i], "-d" ) )
        {
            decryptMode = true;
        }
        else
        {
            if     ( 0 == paramIndex ) { bufferPtr = key; bufferSizePtr = &keySize; }
            else if( 1 == paramIndex ) { bufferPtr = block; bufferSizePtr = &blockSize; }
            else
            {
                printf( "Invalid syntax\n" );
                exit( 1 );
            }

            ReadHexData( ArgV[i], bufferPtr, bufferSizePtr );
            paramIndex += 1;
        }
    }

    if( 128/8 != blockSize )
    {
        printf( "Invalid block size, must be 128 bits (was %u bits)\n", blockSize*8 );
        exit( 1 );
    }

    switch( keySize )
    {
        case 128/8: AesInitialise( &aesContext, key, AES_KEY_SIZE_128 ); break;
        case 192/8: AesInitialise( &aesContext, key, AES_KEY_SIZE_192 ); break;
        case 256/8: AesInitialise( &aesContext, key, AES_KEY_SIZE_256 ); break;
        default:
            printf( "Invalid key size, must be 128, 192, or 256 bits (was %u bits)\n", keySize*8 );
            exit( 1 );
    }

    if( decryptMode )
    {
        AesDecryptInPlace( &aesContext, block );
    }
    else
    {
        AesEncryptInPlace( &aesContext, block );
    }

    // Display
    for( i=0; i<sizeof(block); i++ )
    {
        printf( "%2.2x", block[i] );
    }
    printf( "\n" );

    return 0;
}
