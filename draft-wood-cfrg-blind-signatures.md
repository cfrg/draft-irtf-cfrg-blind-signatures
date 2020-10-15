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
for untraceable payments {{Chaum83}}.

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
interact to compute `sig = Sign(skS, msg)`, where `msg` is the message to be signed
and `skS` is the server's private key. In this protocol, the server learns nothing
of `msg`, whereas the client learns `s` but nothing of `skS`.

The core issuance protocol runs as follows:

~~~
   Client(pkS, msg)                         Server(skS, pkS)
  ----------------------------------------------------------
    blinded_message, blind_inv = Blind(msg)

                      blinded_message
                        ---------->

           evaluated_message = Evaluate(skS, blinded_message)

                         evaluation
                        <----------

    pre_signature = Unblind(evaluated_message, blind_inv)
    sig = Finalize(msg, pre_signature, pkS)
~~~

Upon completion, clients can verify a blind signature `sig` over input `msg` using
the server public key `pkS`.

## RSA-PSS Blind Signature Instantiation

Section 8.1 of {{!RFC8017}} defines RSASSA-PSS RSAE, which is a signature algorithm
using RSASSA-PSS {{RFC8017}} with mask generation function 1. In this section, we
define a blinded variant of this algorithm.

### Signature Generation

~~~
rsassa_pss_sign_blind(skS, msg)

Parameters:
- k_bits, the length in bits of the RSA modulus n
- L, \lambda(n) as defined in {{RFC8017}}

Inputs:
- msg, message to be signed, an octet string

Outputs:
- blinded_message, an octet string of length k
- blind_inv, an octet string of length k

Errors:
- "message too long": XXX
- "encoding error": XXX

Steps:
1. encoded_message = EMSA-PSS-ENCODE(msg, k_bits - 1)
2. If EMSA-PSS-ENCODE outputs an error, output an error and stop.
3. m = OS2IP(encoded_message)
4. r = RandomInteger(0, n - 1)
5. z = RSASP1((n, r), m)
6. r_inv = MultInverse(r, L)
7. blinded_message = I2OSP(z, k)
8. blind_inv = I2OSP(r, k)
8. return blinded_message, blind_inv
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
rsassa_pss_sign_unblind(evaluated_message, blind_inv)

Parameters:
- k, the length in octets of the RSA modulus n

Inputs:
- evaluated_message, signed and blinded element, an octet string of length k
- blind_inv, inverse of the blind, an octet string of length k

Outputs:
- pre_sig, an octet string of length k

Steps:
1. s = OS2IP(evaluated_message)
2. r_inv = OS2IP(blind_inv)
3. pre_sig = RSASP1(s, (n, r_inv))
4. output pre_sig
~~~

~~~
rsassa_pss_sign_finalize(msg, pre_sig, pkS)

Inputs:
- msg, message to be signed, an octet string
- pre_sig, an octet string of length k
- pkS, server public key

Outputs:
- sig, an octet string of length k

Errors:
- "invalid signature"

Steps:
1. sig = I2OSP(pre_sig, k)
2. result = rsassa_pss_sign_verify(msg, sig, pkS)
3. If result = true, return sig, else output "invalid signature" and stop
~~~

### Signature Verification

~~~
rsassa_pss_sign_verify(msg, sig, pkS)

Parameters:
- L_em = ceil((k_bits - 1)/8), where k_bits is the length in bits of the RSA modulus n

Inputs:
- msg, message to be signed, an octet string
- sig, message signature, an octet string of length k
- pkS, server public key

Outputs:
- valid, a boolean value that is true if the signature is valid, and false otherwise

Steps:
1. If len(s) != k, output false
2. s = OS2IP(sig)
3. m = RSASP1(pkS, s)
4. If RSAVP1 output "signature representative out of range", output false
5. encoded_message = I2OSP(m, L_em)
6. result = EMSA-PSS-VERIFY(msg, encoded_message, k_bits - 1).
7. If result = "consistent", output true, otherwise output false
8. output result
~~~

# Security Considerations {#sec-considerations}

TODO

## Partial Blindness

TODO(caw): use different public keys

## Message Robustness

TODO(caw): how does the signer check the contents of the msg before signing it? ZKPs if necessary

## Alternatives

TODO(caw): summarize the variants below

- RSA-PKCS1v1.5
- Blind Schnorr
- Clause Blind Schnorr
- Blind BLS

# IANA Considerations

TODO

--- back

# Test Vectors
