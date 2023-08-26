Ephemeral FrodoKEM
==================

This variant, referred to as **eFrodoKEM**, does not include countermeasures against multi-ciphertext attacks and, thus, it is only suitable for applications in which not many ciphertexts are encrypted to a single public-key.

The public API in the software is designed to be extra conservative and forces a fresh key pair per connection (key generation and encapsulation are exposed through a unified API; see [`ekem.c`](src/ekem.c)).
Any modification to the code to enable some key reuse should be done with care and only if a given application guarantees a limited number of ciphertexts per public key.


## Contents

* [`KAT` folder](KAT/): Known Answer Test (KAT) files for the KEM.
* [`src` folder](src/): C and header files. Public APIs can be found in [`api_efrodo640.h`](src/api_efrodo640.h), [`api_efrodo976.h`](src/api_efrodo976.h) and [`api_efrodo1344.h`](src/api_efrodo1344.h).
    * [Optimized matrix operations](src/frodo_macrify.c): optimized implementation of the matrix operations. 
    * [Reference matrix operations](src/frodo_macrify_reference.c): reference implementation of the matrix operations.
    * [`src/aes` folder](src/aes/): AES implementation.
    * [`src/random` folder](src/random/): randombytes function using the system random number generator.
    * [`src/sha3` folder](src/sha3/): SHA-3 / SHAKE128 / SHAKE256 implementation.  
* [`tests` folder](tests/): test files.  
* [`VisualStudio` folder](VisualStudio/): Visual Studio 2022 files for compilation in Windows.
* [`Makefile`](Makefile): Makefile for compilation using the GNU GCC or clang compilers on Unix-like operative systems. 
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
$ ./efrodo640/test_KEM
$ ./efrodo976/test_KEM
$ ./efrodo1344/test_KEM
```

To run the implementations against the KATs, execute:

```sh
$ ./efrodo640/PQCtestKAT_kem
$ ./efrodo976/PQCtestKAT_kem
$ ./efrodo1344/PQCtestKAT_kem
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
$ ./efrodo640/test_KEM
$ ./efrodo976/test_KEM
$ ./efrodo1344/test_KEM
```

To run the implementations against the KATs, execute:

```sh
$ ./efrodo640/PQCtestKAT_kem_shake
$ ./efrodo976/PQCtestKAT_kem_shake
$ ./efrodo1344/PQCtestKAT_kem_shake
```

### Additional options

These are all the available options for compilation:

```sh
$ make CC=[gcc/clang] ARCH=[x64/x86/ARM/PPC/s390x] OPT_LEVEL=[REFERENCE/FAST_GENERIC/FAST] GENERATION_A=[AES128/SHAKE128] USE_OPENSSL=[TRUE/FALSE]
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

Open the solution file [`efrodoKEM.sln`](VisualStudio/efrodoKEM.sln) in Visual Studio, and choose either x64 or x86 from the platform menu. 
Make sure `Fast_generic` is selected in the configuration menu. Finally, select "Build Solution" from the "Build" menu. 

### Running the tests:

After building the solution file, there should be three executable files: `test_KEM640.exe`, `test_KEM976.exe` and `test_KEM1344.exe`, to run tests for the KEM. 

### Using the library:

After building the solution file, add the generated `eFrodoKEM-640.lib`, `eFrodoKEM-976.lib` and `eFrodoKEM-1344.lib` library files to the set of References for a project, 
and add [`api_efrodo640.h`](src/api_efrodo640.h), [`api_efrodo976.h`](src/api_efrodo976.h) and [`api_efrodo1344.h`](src/api_efrodo1344.h) to the list of header files of a project.

## Python3 implementation

The [`python3`](python3) folder contains a Python3 implementation of FrodoKEM.
This reference implementation is a line-by-line transcription of the pseudocode from the [FrodoKEM specification](https://frodokem.org) and includes extensive comments.
The file [`efrodokem.py`](python3/efrodokem.py) contains a Python3 class implementing all 6 variants of eFrodoKEM.
The file [`nist_kat.py`](python3/nist_kat.py) contains a minimal Python port of the known answer test (KAT) code; it should generate the same output as the C version for the first test vector (except that the line `seed = ` will differ). 

It can be run as follows:

```sh
pip3 install bitstring cryptography
cd python3
python3 nist_kat.py
```

**WARNING**: This Python3 implementation of eFrodoKEM is not designed to be fast or secure, and may leak secret information via timing or other side channels; it should not be used in production environments.