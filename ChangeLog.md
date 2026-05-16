# Changelog

## Version 3.0.0 — May 2026

* **Compatibility warning:** the AES-CTR fix below changes the
  keystream produced when the cipher is called with sub-block chunks
  (smaller than 16 bytes) or when a call leaves the stream index
  mid-block. One-shot AES-CTR encryption was already correct and is
  unaffected. Ciphertext written by 2.x via the chunked path is
  non-standard and cannot be decrypted by 3.0.0 — decrypt with the
  previous release and re-encrypt with 3.0.0 to migrate stored data.
* Bugfix: AES-CTR produced an incorrect keystream when called with
  sub-block chunks (smaller than the 16-byte block size). Ciphertext
  did not match other AES-CTR implementations; intra-library
  encrypt/decrypt still round-tripped, which had masked the defect.
* Bugfix: `Rc4Initialise` and `Rc4XorWithKey` were undefined behaviour
  when `KeySize=0`. Both now return `int` (-1 on invalid key, 0
  otherwise). Existing callers that ignored the previous `void` return
  continue to compile.
* Bugfix: `Sha512Calculate` (added in 2.3.0) was implemented but never
  declared in `WjCryptLib_Sha512.h`. The declaration has been added.
* Bugfix: WjCryptLibTest AES-CBC had a stack buffer overflow that
  corrupted the IV. The CBC algorithm itself was unaffected.
* Bugfix: `HexToBytes` in WjCryptLibTest now takes a `MaxDataSize` and
  refuses to overflow the destination buffer.
* `Digest` parameter direction corrected from `[in]` to `[out]` on
  `Sha1Finalise`, `Sha1Calculate`, `Sha256Calculate`, `Md5Finalise`,
  `Md5Calculate`, and `Sha512Calculate`.
* `WjCryptLib_Sha1.c` `TransformFunction` workspace is now declared as
  `CHAR64LONG16` directly rather than a `uint8_t[64]` cast (was UB on
  strict-alignment targets).
* Defensive `curlen` bounds check in `Sha256Update` and `Sha512Update`
  changed to `>=` for consistency with the corresponding `Finalise`.
* `AES_KEY_SIZE_128` replaced with `AES_BLOCK_SIZE` for the 16-byte
  cipher blocks in `AesCtrXor`.
* Removed unused `STORE64H` macro from `WjCryptLib_AesCbc.c`.
* `WjCryptLib_Aes.h` documentation now refers to the unified
  `AesInitialise` rather than the non-existent
  `AesInitialise128/192/256`.
* Added a `Makefile` convenience wrapper around CMake with `make build`,
  `make test`, `make clean`, and `make help` (the default target).
  Works on macOS, Linux, and Windows native with GNU Make.
* Registered the test harness with ctest, so `make test` works
  regardless of cmake generator (including multi-config generators
  such as Visual Studio).
* Added direct test coverage for the `*Calculate` one-shot functions,
  AES-CTR sub-block chunked consistency, RC4 zero-length key rejection,
  and `HexToBytes` bounds checking.

## Version 2.3.0 — March 2018

* Added AES-CBC module.
* Added functions `Md5Calculate`, `Sha1Calculate`, `Sha256Calculate` and
  `Sha512Calculate` to calculate a hash in one call.
* Added function `Rc4XorWithKey` to encrypt/decrypt a buffer with RC4 in
  one call.
* Bugfix: `AesInitialise` now returns -1 if an invalid key size is
  provided. Previously it would return 0 despite what was documented.

## Version 2.2.0 — January 2018

* Added AES-OFB module.
* File names have been changed to have the prefix `WjCryptLib_` rather
  than `CryptLib_`.
* Removed compiled binaries from the source tree.

## Version 2.1.0 — December 2017

* Changed implementation of AES to one which is almost 5 times as fast.
  The new implementation comes from LibTomCrypt. The newer
  implementation produces a larger binary size as a trade-off.
* AES-CTR module now supports OpenMP and when compiled with OpenMP will
  run in parallel giving a much greater speed.
* Changed interface for initialisation functions for both AES and AES-CTR
  to match RC4 (the context is the first parameter, not the last).

## Version 2.0.0 — December 2017

* Added AES and AES-CTR modules. AES-CTR conforms to the same counter
  mode used with AES in OpenSSL.
* All algorithms now work on big-endian architectures.
* Now uses CMake for building rather than make files and Visual Studio
  projects. CMake will generate whatever build system is required.
* Input function parameters are now marked `const`.
* File names have been changed to have the prefix `CryptLib_` rather
  than `Lib`.
* Various formatting changes to the files.

## Version 1.0.0 — June 2013

Initial release. Contains the following algorithms:

* MD5
* SHA-1
* SHA-256
* SHA-512
* RC4
