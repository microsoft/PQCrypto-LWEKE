FrodoKEM: Learning with Errors Key Encapsulation
================================================

This C library implements **FrodoKEM**, an IND-CCA secure key encapsulation (KEM) protocol based on the well-studied Learning with Errors (LWE) problem [1], which in turn has close connections to conjectured-hard problems on generic, "algebraically unstructured" lattices.  This package also includes a Python reference implementation.
**FrodoKEM** is conjectured to be secure against quantum computer attacks.

Concretely, this library includes the following KEM schemes using AES128 for the generation of the public matrix "A":

* FrodoKEM-640-AES:  matching the post-quantum security of AES128.
* FrodoKEM-976-AES:  matching the post-quantum security of AES192.
* FrodoKEM-1344-AES: matching the post-quantum security of AES256.

And the following KEM schemes using SHAKE128 for the generation of the public matrix "A":

* FrodoKEM-640-SHAKE:  matching the post-quantum security of AES128.
* FrodoKEM-976-SHAKE:  matching the post-quantum security of AES192.
* FrodoKEM-1344-SHAKE: matching the post-quantum security of AES256.

The library was developed by the [FrodoKEM team](https://frodokem.org/#team) and [Microsoft Research](http://research.microsoft.com/) for experimentation purposes.

## Contents

* [`KAT` folder](KAT/): Known Answer Test (KAT) files for the KEM.
* [`src` folder](src/): C and header files. Public APIs can be found in [`api_frodo640.h`](src/api_frodo640.h), [`api_frodo976.h`](src/api_frodo976.h) and [`api_frodo1344.h`](src/api_frodo1344.h).
    * [Optimized matrix operations](src/frodo_macrify.c): optimized implementation of the matrix operations. 
    * [Reference matrix operations](src/frodo_macrify_reference.c): reference implementation of the matrix operations.
    * [`src/aes` folder](src/aes/): AES implementation.
    * [`src/random` folder](src/random/): randombytes function using the system random number generator.
    * [`src/sha3` folder](src/sha3/): SHA-3 / SHAKE128 / SHAKE256 implementation.  
* [`tests` folder](tests/): test files.  
* [`VisualStudio` folder](VisualStudio/): Visual Studio 2015 files for compilation in Windows.
* [`Makefile`](Makefile): Makefile for compilation using the GNU GCC or clang compilers on Unix-like operative systems. 
* [`LICENSE`](LICENSE): MIT license file.
* [`README.md`](README.md): this readme file.
* [`python3` folder](python3): a Python3 reference implementation

### Complementary crypto functions

Random values are generated with /dev/urandom on Unix-like operative systems, and CNG's BCryptGenRandom function in Windows. 
Check the folder [`random`](src/random/) for details.

The library includes standalone implementations of AES and SHAKE. The generation of the matrix
"A" (see the specification document [1]) can be carried out with either AES128 or SHAKE128. By
default AES128 is used.

There are two options for AES: the standalone implementation that is included in the software or
OpenSSL's AES implementation. OpenSSL's AES implementation is used by default.

## Supported Platforms

The FrodoKEM library is supported on a wide range of platforms including x64, x86, ARM and PowerPC devices running Windows, Linux or macOS,
and supports both little-endian and big-endian formats. 
We have tested the library with Microsoft Visual Studio 2015, GNU GCC v7.2, and clang v3.8.
See instructions below to choose an implementation option and compile on one of the supported platforms.

## Implementation Options

 The following implementation options are available:
- Reference portable implementation enabled by setting `OPT_LEVEL=REFERENCE`. 
- Optimized portable implementation enabled by setting `OPT_LEVEL=FAST_GENERIC`. 
- Optimized x64 implementation using AVX2 intrinsics and AES-NI instructions enabled by setting `ARCH=x64` and `OPT_LEVEL=FAST`.

Follow the instructions in the sections "_Instructions for Linux_" or "_Instructions for Windows_" below to configure these different implementation options.

## Instructions for Linux 

### Using AES128

By simply executing:

```sh
$ make
```

the library is compiled for x64 using gcc, and optimization level `FAST`, which uses AVX2 instrinsics. 
AES128 is used by default to generate the matrix "A". For AES, OpenSSL's AES implementation is used by default.

Testing and benchmarking results are obtained by running:

```sh
$ ./frodo640/test_KEM
$ ./frodo976/test_KEM
$ ./frodo1344/test_KEM
```

To run the implementations against the KATs, execute:

```sh
$ ./frodo640/PQCtestKAT_kem
$ ./frodo976/PQCtestKAT_kem
$ ./frodo1344/PQCtestKAT_kem
```

### Using SHAKE128

By executing:

```sh
$ make GENERATION_A=SHAKE128
```

the library is compiled for x64 using gcc, and optimization level `FAST`, which uses AVX2 instrinsics. 
SHAKE128 is used to generate the matrix "A".

Testing and benchmarking results are obtained by running:

```sh
$ ./frodo640/test_KEM
$ ./frodo976/test_KEM
$ ./frodo1344/test_KEM
```

To run the implementations against the KATs, execute:

```sh
$ ./frodo640/PQCtestKAT_kem_shake
$ ./frodo976/PQCtestKAT_kem_shake
$ ./frodo1344/PQCtestKAT_kem_shake
```

### Additional options

These are all the available options for compilation:

```sh
$ make CC=[gcc/clang] ARCH=[x64/x86/ARM/PPC] OPT_LEVEL=[REFERENCE/FAST_GENERIC/FAST] GENERATION_A=[AES128/SHAKE128] USE_OPENSSL=[TRUE/FALSE]
```

Note that the `FAST` option is only available for x64 with support for AVX2 and AES-NI instructions.
The USE_OPENSSL flag specifies whether OpenSSL's AES implementation is used (`=TRUE`) or if the
standalone AES implementation is used (`=FALSE`). Therefore, this flag only applies when `GENERATION_A=
AES128` (or if `GENERATION_A` is left blank).

If OpenSSL is being used and is installed in an alternate location, use the following make options:
    
```sh
OPENSSL_INCLUDE_DIR=/path/to/openssl/include
OPENSSL_LIB_DIR=/path/to/openssl/lib
```

The program tries its best at auto-correcting unsupported configurations. 
For example, since the `FAST` implementation is currently only available for x64 doing `make ARCH=x86 OPT_LEVEL=FAST` 
is actually processed using `ARCH=x86 OPT_LEVEL=FAST_GENERIC`.

## Instructions for Windows

### Building the library with Visual Studio:

Open the solution file [`frodoKEM.sln`](VisualStudio/frodoKEM.sln) in Visual Studio, and choose either x64 or x86 from the platform menu. 
Make sure `Fast_generic` is selected in the configuration menu. Finally, select "Build Solution" from the "Build" menu. 

### Running the tests:

After building the solution file, there should be three executable files: `test_KEM640.exe`, `test_KEM976.exe` and `test_KEM1344.exe`, to run tests for the KEM. 

### Using the library:

After building the solution file, add the generated `FrodoKEM-640.lib`, `FrodoKEM-976.lib` and `FrodoKEM-1344.lib` library files to the set of References for a project, 
and add [`api_frodo640.h`](src/api_frodo640.h), [`api_frodo976.h`](src/api_frodo976.h) and [`api_frodo1344.h`](src/api_frodo1344.h) to the list of header files of a project.

## Python3 implementation

The [`python3`](python3) folder contains a Python3 implementation of FrodoKEM.
This reference implementation is a line-by-line transcription of the pseudocode from the [FrodoKEM specification](https://frodokem.org) and includes extensive comments.
The file [`frodokem.py`](python3/frodokem.py) contains a Python3 class implementing all 6 variants of FrodoKEM.
The file [`nist_kat.py`](python3/nist_kat.py) contains a minimal Python port of the known answer test (KAT) code; it should generate the same output as the C version for the first test vector (except that the line `seed = ` will differ). 

It can be run as follows:

```sh
pip3 install bitstring cryptography
cd python3
python3 nist_kat.py
```

**WARNING**: This Python3 implementation of FrodoKEM is not designed to be fast or secure, and may leak secret information via timing or other side channels; it should not be used in production environments.

## License

This software is licensed under the MIT License; see the LICENSE file for details.
The Python3 implementation is licensed under the Creative Commons Zero v1.0 Universal license.
It includes some third party modules that are licensed differently. In particular:

- `src/aes/aes_c.c`: public domain
- `src/aes/aes_ni.c`: public domain
- `src/sha3/fips202.c`: public domain
- `src/sha3/fips202x4.c`: public domain
- `src/sha3/keccak4x`: all files in this folder are public domain ([CC0](http://creativecommons.org/publicdomain/zero/1.0/)), excepting
- `src/sha3/keccak4x/brg_endian.h` which is copyrighted by Brian Gladman and comes with a BSD 3-clause license.
- `tests/ds_benchmark.h`: public domain
- `tests/PQCtestKAT_kem<#>.c`: copyrighted by Lawrence E. Bassham 
- `tests/PQCtestKAT_kem<#>_shake.c`: copyrighted by Lawrence E. Bassham
- `tests/rng.c`: copyrighted by Lawrence E. Bassham 

# References

[1]  Erdem Alkim, Joppe W. Bos, Léo Ducas, Karen Easterbrook, Brian LaMacchia, Patrick Longa, Ilya Mironov, Michael Naehrig, Valeria Nikolaenko, Chris Peikert, Ananth Raghunathan, and Douglas Stebila, 
"FrodoKEM: Learning With Errors Key Encapsulation". Submission to the NIST Post-Quantum Standardization project, 2017-2019. The round 2 specification of FrodoKEM is available [`here`](https://frodokem.org/files/FrodoKEM-specification-20190330.pdf). 

[2]  Joppe W. Bos, Craig Costello, Léo Ducas, Ilya Mironov, Michael Naehrig, Valeria Nikolaenko, Ananth Raghunathan, and Douglas Stebila, 
"Frodo: Take off the ring! Practical, quantum-secure key exchange from LWE". 
ACM CCS 2016, 2016. The preprint version is available [`here`](http://eprint.iacr.org/2016/659). 

# Contributing

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
