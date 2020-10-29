---
title: Blind Signatures
abbrev: Blind Signatures
docname: draft-wood-cfrg-blind-signatures-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    email: caw@heapingbits.net

informative:
  Chaum83:
    title: Blind Signatures for Untraceable Payments
    target: http://sceweb.sce.uhcl.edu/yang/teaching/csci5234WebSecurityFall2011/Chaum-blind-signatures.PDF
    date: false
    authors:
      -
        ins: D. Chaum
        org: University of California, Santa Barbara, USA

--- abstract

This document specifies RSA-based blind signatures, first introduced by Chaum
for untraceable payments {{Chaum83}}.

--- middle

# Introduction

This document specifies RSA-based blind signatures, first introduced by Chaum
for untraceable payments {{Chaum83}}. It extends RSA-PSS encoding specified in
{{!RFC8017}} to enable blind signature support.

# Requirements Notation

{::boilerplate bcp14}

# Notation

The following terms are used throughout this document to describe the
protocol operations in this document:

- I2OSP and OS2IP: Convert a byte string to and from a non-negative integer as
  described in {{!RFC8017}}. Note that these functions operate on byte strings
  in big-endian byte order.
- RandomInteger(M, N): Generate a random, uniformly distributed integer r
  such that M < R <= N.
- MultInverse(n, p): Compute the multiplicative inverse of n mod p.

# Blind Signature Protocol

In this section, we define the blind signature protocol wherein a client and server
interact to compute `sig = Sign(skS, msg, aux)`, where `msg` is the private message
to be signed, `aux` is the public auxiliary information included in the signature
computation, and `skS` is the server's private key. In this protocol, the server
learns nothing of `msg`, whereas the client learns `s` and nothing of `skS`.

The core issuance protocol runs as follows:

~~~
   Client(pkS, msg, aux)                Server(skS, pkS, aux)
  ----------------------------------------------------------
    blinded_message, blind_inv = Blind(pkS, msg, aux)

                      blinded_message
                        ---------->

           evaluated_message = Evaluate(skS, blinded_message, aux)

                         evaluation
                        <----------

    sig = Finalize(pkS, msg, aux, evaluated_message, blind_inv)
~~~

Upon completion, clients can verify a blind signature `sig` over private input
message `msg` and public input `aux` using the server public key `pkS` as follows.

~~~
valid = Verify(pkS, msg, aux, sig)
~~~

## RSA-PSS Blind Signature Instantiation

Section 8.1 of {{!RFC8017}} defines RSASSA-PSS RSAE, which is a signature algorithm
using RSASSA-PSS {{RFC8017}} with mask generation function 1. In this section, we
define a blinded variant of this algorithm.

### Signature Generation

[[OPEN ISSUE: should this take `msg` as input, or `msg_hash`?]]

~~~
rsassa_pss_sign_blind(pkS, msg)

Parameters:
- k_bits, the length in bits of the RSA modulus n

Inputs:
- pkS, server public key (n, e)
- msg, message to be signed, an octet string

Outputs:
- blinded_message, an octet string of length k
- blind_inv, an octet string of length k

Errors:
- "message too long": Raised when the input message is too long.
- "encoding error": Raised when the input message fails encoding.

Steps:
1. encoded_message = EMSA-PSS-ENCODE(msg, k_bits - 1)
2. If EMSA-PSS-ENCODE outputs an error, output an error and stop.
3. m = OS2IP(encoded_message)
4. r = RandomInteger(0, n - 1)
5. x = RSASP1(pkS, r)
6. z = m * x mod n
7. r_inv = MultInverse(r, n)
8. blinded_message = I2OSP(z, k)
9. blind_inv = I2OSP(r, k)
10. return blinded_message, blind_inv
~~~

~~~
rsassa_pss_sign_evaluate(skS, blinded_msg)

Parameters:
- k, the length in octets of the RSA modulus n

Inputs:
- blinded_msg, encoded and blinded message to be signed, an octet string

Outputs:
- encoded_message, an octet string of length k

Steps:
1. m = OS2IP(blinded_msg)
2. s = RSASP1(skS, m)
3. encoded_message = I2OSP(s, k)
4. output encoded_message
~~~

~~~
rsassa_pss_sign_finalize(pkS, msg, evaluated_message, blind_inv)

Inputs:
- pkS, server public key
- msg, message to be signed, an octet string
- evaluated_message, signed and blinded element, an octet string of length k
- blind_inv, inverse of the blind, an octet string of length k

Outputs:
- sig, an octet string of length k

Errors:
- "invalid signature": Raised when the signature is invalid

Steps:
1. z = OS2IP(evaluated_message)
2. r_inv = OS2IP(blind_inv)
3. s = z * r_inv mod n
4. result = rsassa_pss_sign_verify(pkS, msg, s)
5. sig = I2OSP(s, k)
6. If result = true, return s, else output "invalid signature" and stop
~~~

### Signature Verification

~~~
rsassa_pss_sign_verify(pkS, msg, sig)

Parameters:
- L_em = ceil((k_bits - 1)/8), where k_bits is the length in bits of the RSA modulus n

Inputs:
- pkS, server public key
- msg, message to be signed, an octet string
- sig, message signature, an octet string of length k

Outputs:
- valid, a boolean value that is true if the signature is valid, and false otherwise

Errors:
- ""

Steps:
1. If len(sig) != k, output false
2. s = OS2IP(sig)
3. m = RSAVP1(pkS, s)
4. If RSAVP1 output "signature representative out of range", output false
5. encoded_message = I2OSP(m, L_em)
6. result = EMSA-PSS-VERIFY(msg, encoded_message, k_bits - 1).
7. If result = "consistent", output true, otherwise output false
8. output result
~~~

### Partially-Blind Key Augmentation

To implement partially blinded signatures, public auxiliary information is used
to augment the public and private keys used during the signature verification.
This section describes how clients and servers augment a public key pair `(pkS, skS)`
using information `aux`.

[[OPEN ISSUE: need to specify H, a one-way hash function into Z_\lambda(n)\*]]
[[OPEN ISSUE: Hash input `aux` into value, that's then hashed into ]]
[[OPEN ISSUE: the augmentation strings MUST be enumerable]]

~~~
rsassa_pss_augment_public_key(pkS = (n, e), aux)

Parameters:
- H(), a one-way hash function

Inputs:
- pkS, server public key (n, e)
- aux, public auxiliary information, an octet string

Steps:
1. c = 2^(k-1) + 2*H(aux) + 1
2. return (n, (e * c))
~~~

~~~
rsassa_pss_augment_private_key(pkS = (n, d), aux)

Parameters:
- H(), a one-way hash function
- L, \lambda(n) as defined in {{RFC8017}}

Inputs:
- skS, server public key (n, d)
- aux, public auxiliary information, an octet string

Steps:
1. c = 2^(k-1) + 2*H(aux) + 1
2. c_inv = ModInverse(c, L)
3. return (n, (d * c))
~~~

# Security Considerations {#sec-considerations}

TODO

## Message Robustness

TODO(caw): how does the signer check the contents of the msg before signing it? ZKPs if necessary

## Alternatives

TODO(caw): summarize the variants below

- RSA-PKCS1v1.5
- Blind Schnorr
- Clause Blind Schnorr
- ABE (https://eprint.iacr.org/2020/1071.pdf)
- Blind BLS

# IANA Considerations

TODO

--- back

# Test Vectors
