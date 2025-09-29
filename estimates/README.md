FrodoKEM: Learning with Errors Key Encapsulation
================================================
Scripts for cryptanalysis estimates (2025 update)
=================================================

This directory contains scripts that generate the updated attack estimates reported in [1].

## Dependencies

- bash, git
- sagemath
- tqdm and tabulate python modules, available to sagemath (see [Python modules](#python-modules))
- lattice-estimator script (see [Lattice estimator](#lattice-estimator))

### Python modules

To install `tqdm` and `tabulate` within sagemath's reach, use
```bash
sage -pip install tqdm tabulate
```

### Lattice estimator

We use the [lattice-estimator](https://github.com/malb/lattice-estimator) script to obtain our attack estimates against Frodo.

To obtain the specific commit of the estimator we used, run:
```bash
bash fetch_estimator.sh
```

## Generate attack and bit-security estimates

After following the steps in [Dependencies](#dependencies), run
```bash
sage estimates.py
```
The output will contain the Core-SVP and Beyond-Core-SVP numbers reported in Section 7 [1].
Note that the rows of the tables output by the script may not be in the same order as those in the manuscript.

The output will also contain single-user single-ciphertext bit-security estimates, following the methodology in Appendix C.1.1 [1].

## Generating decryption error probabilities

The code used to compute the expected decryption error probabilities were originally published in the NIST PQC Round 3 submission package, available at [frodokem.org](https://frodokem.org/), as part of the parameter-search scripts.

## References

[1] Lewis Glabush, Patrick Longa, Michael Naehrig, Chris Peikert, Douglas Stebila, and Fernando Virdia,
"FrodoKEM: A CCA-Secure Learning With Errors Key Encapsulation Mechanism". IACR Communications in Cryptology (to appear), 2025.