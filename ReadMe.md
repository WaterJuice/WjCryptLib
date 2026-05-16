# WjCryptLib

WjCryptLib is a public-domain collection of cryptographic primitives in
C: MD5, SHA-1, SHA-256, SHA-512, RC4, AES, and AES in CBC, CTR and OFB
modes. Each module is independent — a single `.c` file and matching
`.h` file are usually all that's needed.

The code is portable across little-endian and big-endian architectures,
builds on macOS, Linux and Windows, and supports OpenMP for parallel
AES-CTR.

*Placed into Public Domain by WaterJuice 2013 – 2026.*

## Algorithms

To use a single algorithm, copy the files listed below into your project.

| Algorithm | Files |
|-----------|-------|
| MD5       | `WjCryptLib_Md5.{h,c}` |
| SHA-1     | `WjCryptLib_Sha1.{h,c}` |
| SHA-256   | `WjCryptLib_Sha256.{h,c}` |
| SHA-512   | `WjCryptLib_Sha512.{h,c}` |
| RC4       | `WjCryptLib_Rc4.{h,c}` |
| AES       | `WjCryptLib_Aes.{h,c}` |
| AES-CBC   | `WjCryptLib_AesCbc.{h,c}` (plus AES) |
| AES-CTR   | `WjCryptLib_AesCtr.{h,c}` (plus AES) |
| AES-OFB   | `WjCryptLib_AesOfb.{h,c}` (plus AES) |

### Algorithm choice

MD5, SHA-1 and RC4 are included for interoperability with existing
systems but are considered cryptographically broken and should not be
used for new work. Prefer SHA-256 or SHA-512 over MD5 and SHA-1, and
prefer an AES mode over RC4.

## Building

The canonical build setup is [`CMakeLists.txt`](CMakeLists.txt). CMake
generates build files for any system — Visual Studio projects on
Windows, Unix Makefiles or Ninja on Linux/macOS, Xcode, and so on.
Install CMake from <https://cmake.org/download/>.

```sh
cmake -S . -B build
cmake --build build
```

A thin [`Makefile`](Makefile) wrapper is provided as a convenience that
delegates everything to CMake. It works on macOS, Linux, and Windows
native when GNU Make is installed:

```sh
make build      # configure and build everything
make test       # build then run the test harness via ctest
make clean      # remove the build tree
make help       # show available targets (default)
```

## Test and demo programs

In the [`projects/`](projects/) directory there are several programs
that compile to command-line executables:

* `WjCryptLibTest` — Verifies every algorithm against known test
  vectors. Useful when porting to a new platform.
* `Md5String`, `Sha1String`, `Sha256String`, `Sha512String` — Compute a
  hash of a string given on the command line.
* `Rc4Output` — Output an RC4 stream as hex.
* `AesBlock` — Encrypt or decrypt a single AES block.
* `AesCtrOutput`, `AesOfbOutput` — Output an AES-CTR or AES-OFB stream
  as hex.

## Changelog

See [ChangeLog.md](ChangeLog.md) for the full version history.

## License

This software is released into the public domain. See [UNLICENSE](UNLICENSE)
for the full text, or refer to <http://unlicense.org/>.
