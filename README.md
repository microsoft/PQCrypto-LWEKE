FrodoKEM: Learning with Errors Key Encapsulation
================================================

This C library implements **FrodoKEM**, an IND-CCA secure key encapsulation (KEM) protocol based on the well-studied Learning with Errors (LWE) problem [1,3], which in turn has close connections to conjectured-hard problems on generic,
"algebraically unstructured" lattices.  This package also includes Python reference implementations. **FrodoKEM** is conjectured to be secure against quantum computer attacks.

**FrodoKEM** consists of two main variants:

* A *standard* variant (simply called **FrodoKEM**) that does not impose any restriction on the reuse of key pairs (i.e., it is suitable for applications in which a large number of ciphertexts may be encrypted to a single public key), and
* An *ephemeral* variant (called **eFrodoKEM**) that is suitable for applications in which not many ciphertexts are encrypted to a single public-key.

In contrast to **eFrodoKEM**, standard **FrodoKEM** uses an enlarged seed for generating the seed for sampling the secret and error matrices, and includes an additional salt in one of the hashing computations in encapsulation and decapsulation.
These countermeasures safeguard standard **FrodoKEM** against some multi-ciphertext attacks. Refer to [3] for more details on these two variants.

Concretely, this library includes the following KEM schemes using AES128 for the generation of the public matrix "A":

* FrodoKEM-640-AES and eFrodoKEM-640-AES:   matching the post-quantum security of AES128.
* FrodoKEM-976-AES and eFrodoKEM-976-AES:   matching the post-quantum security of AES192.
* FrodoKEM-1344-AES and eFrodoKEM-1344-AES: matching the post-quantum security of AES256.

And the following KEM schemes using SHAKE128 for the generation of the public matrix "A":

* FrodoKEM-640-SHAKE and eFrodoKEM-640-SHAKE:   matching the post-quantum security of AES128.
* FrodoKEM-976-SHAKE and eFrodoKEM-976-SHAKE:   matching the post-quantum security of AES192.
* FrodoKEM-1344-SHAKE and eFrodoKEM-1344-SHAKE: matching the post-quantum security of AES256.

The label "eFrodoKEM" corresponds to the ephemeral variants.

The library was developed by the [FrodoKEM team](https://frodokem.org/#team) and [Microsoft Research](http://research.microsoft.com/) for experimentation purposes.

## Contents

* [`eFrodoKEM` folder](eFrodoKEM/): C and Python3 implementations of eFrodoKEM.
* [`FrodoKEM` folder](FrodoKEM/): C and Python3 implementations of standard FrodoKEM.
* [`LICENSE`](LICENSE): MIT license file.
* [`README.md`](README.md): this readme file.

## Supported Platforms

The FrodoKEM library is supported on a wide range of platforms including x64, x86, ARM, PowerPC and s390x processors running Windows, Linux or macOS,
and supports both little-endian and big-endian formats. 
We have tested the library with Microsoft Visual Studio, GNU GCC, and clang.

## License

This software is licensed under the MIT License; see the LICENSE file for details.
The Python3 implementation is licensed under the Creative Commons Zero v1.0 Universal license.
It includes some third party modules that are licensed differently. In particular:

- `<FrodoKEM_variant>/src/aes/aes_c.c`: public domain
- `<FrodoKEM_variant>/src/aes/aes_ni.c`: public domain
- `<FrodoKEM_variant>/src/sha3/fips202.c`: public domain
- `<FrodoKEM_variant>/src/sha3/fips202x4.c`: public domain
- `<FrodoKEM_variant>/src/sha3/keccak4x`: all files in this folder are public domain ([CC0](http://creativecommons.org/publicdomain/zero/1.0/)), excepting
- `<FrodoKEM_variant>/src/sha3/keccak4x/brg_endian.h` which is copyrighted by Brian Gladman and comes with a BSD 3-clause license.
- `<FrodoKEM_variant>/tests/ds_benchmark.h`: public domain
- `<FrodoKEM_variant>/tests/PQCtestKAT_kem<#>.c`: copyrighted by Lawrence E. Bassham 
- `<FrodoKEM_variant>/tests/PQCtestKAT_kem<#>_shake.c`: copyrighted by Lawrence E. Bassham
- `<FrodoKEM_variant>/tests/rng.c`: copyrighted by Lawrence E. Bassham 

# References

[1]  Erdem Alkim, Joppe W. Bos, Léo Ducas, Karen Easterbrook, Brian LaMacchia, Patrick Longa, Ilya Mironov, Michael Naehrig, Valeria Nikolaenko, Chris Peikert, Ananth Raghunathan, and Douglas Stebila, 
"FrodoKEM: Learning With Errors Key Encapsulation". Submission to the NIST Post-Quantum Standardization project, 2021-2023. The round 3 specification of FrodoKEM is available [`here`](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf). 

[2]  Joppe W. Bos, Craig Costello, Léo Ducas, Ilya Mironov, Michael Naehrig, Valeria Nikolaenko, Ananth Raghunathan, and Douglas Stebila, 
"Frodo: Take off the ring! Practical, quantum-secure key exchange from LWE". 
ACM CCS 2016, 2016. The preprint version is available [`here`](http://eprint.iacr.org/2016/659). 

[3]  FrodoKEM team, "FrodoKEM: Learning With Errors Key Encapsulation - Preliminary Draft Standards". Submission to ISO/IEC JTC1/SC27/WG2, 2023. The preliminary draft is available [`here`](https://frodokem.org/files/FrodoKEM-ISO-20230314.pdf).

# Contributing

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
