CryptLib
========

CryptLib is a collection of cryptographic functions written in C. Each
module is fully independent and generally requires only a single .c file
and a a single .h file. AES-CTR does depend on the AES module, so in this
case all four files are needed.

The functions are designed to be portable and have been tested on both
a Little-Endian and a Big-Endian architecture

The library and the demo programs can be built using CMake to generate
a build setup for any system, including Visual Studio on Windows and
Make or Ninja for Linux. Refer to cmake.org to get CMake.

*Placed into Public Domain by WaterJuice 2013 - 2017*

Version 2.0.0 - December 2017
-----------------------------

Changes:

* Added AES and AES-CTR modules. AES-CTR conforms to the same counter
mode used with AES in *OpenSSL*.
* All algorithms now work on Big-Endian architectures.
* Now uses CMake for building rather than make files and Visual Studio
projects. CMake will generate whatever system is required.
* Input function parameters are now marked `const`
* File names have been changed to have the prefix `CryptLib_` rather
than `Lib`.
* Various formatting changes to the files.

To use the library functions, only the following files are required,
depending on what cryptographic functions are wanted.

* MD5 - (CryptLib_Md5.h, and CryptLib_Md5.c)
* SHA1 - (CryptLib_Sha1.h, and CryptLib_Sha1.c)
* SHA256 - (CryptLib_Sha256.h, and CryptLib_Sha256.c)
* SHA512 - (CryptLib_Sha512.h, and CryptLib_Sha512.c)
* RC4 - (CryptLib_Rc4.h, and CryptLib_Rc4.c)
* AES - (CryptLib_Aes.h, and CryptLib_Aes.c)
* AES-CTR - (CryptLib_AesCtr.h, and CryptLib_AesCtr.c, CryptLib_Aes.h,
  and CryptLib_Aes.c)
             

Version 1.0.0 - June 2013
-------------------------

To use the library functions, only the following files are required,
depending on what cryptographic functions are wanted.

* MD5 - (LibMd5.h, and LibMd5.c)
* SHA1 - (LibSha1.h, and LibSha1.c)
* SHA256 - (LibSha256.h, and LibSha256.c)
* SHA512 - (LibSha512.h, and LibSha512.c)
* RC4 - (LibRc4.h, and LibRc4.c)

Test Programs
-------------

In the projects directory there are several programs that compile to
command line executables. One is CryptLibTest. This tests the algorithms
against known test vectors. If compiling on a different system this
is useful to verify that the results are still valid.

Additionally there are sample programs that demonstrate the functions. For
each of the hash functions there is a program that creates a hash from a
string given on command line. For RC4 and AES-CTR there are programs that
output the stream in hex.

* Md5String
* Sha1String
* Sha256String
* Sha512String
* Rc4Output
* AesBlock
* AesCtrOutput

Executables
-----------

Included in the Exe directory are executables of the above programs for Windows,
MacOS, and Linux. All of them are compiled for x64 versions of the operating
systems. 

License
=======

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>

