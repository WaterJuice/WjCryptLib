CryptLib
========

CryptLib is a collection of cryptographic functions written in C. Each
module is fully independent and requires only a single .c file and a 
a single .h file. The functions are designed to be portable, however
they do require a Little-Endian processor.

The makefile is for gnu make and works on Linux, OSX, Cygwin.
It also works on Windows with VSS if cygwin (or some other gnu make) is
setup and the environment has been setup correctly. 

A Visual Studio 2010 solution file also exists, which has project files.
This can be used instead of the makefile for VS2010.

*Created June 2013*             

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
is useful to verify that the results are still valid. For example if you
compile on a Big-Endian system then some of the functions will undoubtable
fail. The test program can be used to verify that the correct modifications
have been made if you wish to adapt the fiules to Big-Endian.

Additionally there are sample programs that demonstrate the functions. For
each of the hash functions there is a program that creates a hash from a
string given on command line. For RC4 there is a program that outputs
the stream in hex.

* Md5String
* Sha1String
* Sha256String
* Sha512String
* Rc4Output

Executables
-----------

Included in the Exe directory are executables of the above programs for Windows,
OSX, and Linux. All of them are compiled for x64 versions of the operating
systems. The Windows one is compiled for Vista and greater. The Linux binaries
are comiled on Ubuntu 12.04. The binaries are built with a dependncy on GLICC2.14
which means it will only load on fairly new versions of Linux. However linux
is the easiest system to build form source as almost every linux platform will
have make and gcc already installed.

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

