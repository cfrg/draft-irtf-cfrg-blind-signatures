---
title: RSA Blind Signatures
abbrev: RSA Blind Signatures
docname: draft-wood-cfrg-rsa-blind-signatures-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: F. Jacobs
    name: Frederic Jacobs
    org: Apple Inc.
    email: frederic.jacobs@apple.com
 -  ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    email: caw@heapingbits.net

informative:
  KLRX20:
    title: "On Pairing-Free Blind Signature Schemes in the Algebraic Group Model"
    target: https://eprint.iacr.org/2020/1071
  BLS-Proposal:
    title: "[Privacy-pass] External verifiability: a concrete proposal"
    target: https://mailarchive.ietf.org/arch/msg/privacy-pass/BDOOhSLwB3uUJcfBiss6nUF5sUA/
    authors:
      -
        ins: W. Ladd
  PolytimeROS:
    title: "On the (in)security of ROS"
    target: https://eprint.iacr.org/2020/945.pdf
  RSA-FDH:
    title: "Random Oracles are Practical: A Paradigm for Designing Efficient Protocols"
    target: https://cseweb.ucsd.edu/~mihir/papers/ro.pdf
    date: October, 1995
    authors:
      -
        ins: M. Bellare
      -
        ins: P. Rogaway
  Chaum83:
    title: Blind Signatures for Untraceable Payments
    target: http://sceweb.sce.uhcl.edu/yang/teaching/csci5234WebSecurityFall2011/Chaum-blind-signatures.PDF
    date: false
    authors:
      -
        ins: D. Chaum
        org: University of California, Santa Barbara, USA
  RemoteTiming:
    title: "Remote Timing Attacks are Practical"
    target: https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf
    date: 2003
    venue: 12th Usenix Security Symposium
    authors:
      -
        ins: D. Boneh
        org: Stanford University
      -
        ins: D. Brumley
        org: Stanford University

--- abstract

This document specifies the RSA-based blind signature scheme with appendix (RSA-BSSA). RSA blind signatures
were first introduced by Chaum for untraceable payments {{Chaum83}}. It extends RSA-PSS encoding specified
in {{!RFC8017}} to enable blind signature support. It also specifies an extension for partially blind signatures.

--- middle

# Introduction

Originally introduced in the context of digital cash systems by Chaum
for untraceable payments {{Chaum83}}, RSA blind signatures turned out to have
a wide range of applications ranging from electric voting schemes to authentication mechanisms.

Recently, interest in blind signatures has grown to address operational shortcomings from ECVOPRFs
for which the private key is required VOPRF evaluations and therefore required for both issuance and
redemption of tokens in anonymous authentication protocols such as Privacy Pass {{?I-D.davidson-pp-protocol}}.
This limitation complicates deployments where it is not desirable to distribute secret keys entities
performing token verification. Additionally, if the private key is kept in a Hardware Security Module,
the number of operations on the key are doubled compared to a scheme where the private key is only
required for issuance of the tokens.

In order to facilitate the deployment of our scheme, we define it in such a way that the resulting (unblinded)
signature can be verified with a standard RSA-PSS library.

Cryptographic signatures provide a primitive that is publicly verifiable and does not require access to
the private key to verify. Moreover, to facilitate protocols that require public metadata as input
into the signature, we specify an extension of the signature scheme that enables partial blindness
through key augmentation.

This document specifies the RSA Blind Signature Scheme with Appendix (RSABSSA), and its extension for partial blindness.

# Requirements Notation

{::boilerplate bcp14}

# Notation

The following terms are used throughout this document to describe the
protocol operations in this document:

- I2OSP and OS2IP: Convert a byte string to and from a non-negative integer as
  described in {{!RFC8017}}. Note that these functions operate on byte strings
  in big-endian byte order.
- random_integer(M, N): Generate a random, uniformly distributed integer r
  such that M < R <= N.
- inverse_mod(n, p): Compute the multiplicative inverse of n mod p.

# Blind Signature Protocol Overview

In this section, we sketch the blind signature protocol wherein a client and server
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

                     evaluated_message
                        <----------

    sig = Finalize(pkS, msg, aux, evaluated_message, blind_inv)
~~~

Upon completion, correctness requires that clients can verify signature `sig` over private
input message `msg` and public input `aux` using the server public key `pkS` as follows.

~~~
valid = Verify(pkS, msg, aux, sig)
~~~

# RSABSSA Signature Instantiation

Section 8.1 of {{!RFC8017}} defines RSASSA-PSS RSAE, which is a signature algorithm
using RSASSA-PSS {{RFC8017}} with mask generation function 1. In this section, we
define RSABSSA, blinded variant of this algorithm.

## Signature Generation {#generation}
~~~
rsabssa_sign(pkS, msg)

Parameters:
- k, the length in bytes of the RSA modulus n
- k_bits, the length in bits of the RSA modulus n

Inputs:
- pkS, server public key (n, e)
- msg, message to be signed, an octet string
- H, the hash function used to hash the message
- MGF, the mask generation function

Outputs:
- blinded_message, an octet string of length k
- blind_inv, an octet string of length k

Errors:
- "message too long": Raised when the input message is too long.
- "encoding error": Raised when the input message fails encoding.

Steps:
1. msg_hash = H(msg)
2. encoded_message = EMSA-PSS-ENCODE(msg_hash, k_bits - 1) with MGF as defined in the parameters.
3. If EMSA-PSS-ENCODE outputs an error, output the error and stop.
4. m = OS2IP(encoded_message)
5. r = random_integer(0, n - 1)
6. x = RSAVP1(pkS, r)
7. z = m * x mod n
8. r_inv = inverse_mod(r, n)
9. If finding the inverse fails, output an "invalid blind" error and stop.
10. blinded_message = I2OSP(z, k)
11. blind_inv = I2OSP(r_inv, k)
12. output blinded_message, blind_inv
~~~

~~~
rsabssa_sign_evaluate(skS, blinded_msg)

Parameters:
- k, the length in octets of the RSA modulus n

Inputs:
- blinded_msg, encoded and blinded message to be signed, an octet string

Outputs:
- evaluated_message, an octet string of length k

Steps:
1. m = OS2IP(blinded_msg)
2. s = RSASP1(skS, m)
3. evaluated_message = I2OSP(s, k)
4. output evaluated_message
~~~

~~~
rsabssa_sign_finalize(pkS, msg, evaluated_message, blind_inv)

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
4. sig = I2OSP(s, k)
5. result = rsassa_pss_sign_verify(pkS, msg, sig)
6. If result = true, output sig, else output "invalid signature" and stop
~~~

## Signature Verification

Signature verification can be performed by invoking the RSASSA-PSS-VERIFY routine defined in {{!RFC3447}}.

~~~
rsabssa_verify(pkS, msg, sig)

Parameters:
- k, the length in octets of the RSA modulus n
- k_bits, the length in bits of the RSA modulus n
- H, the hash function used to hash the message
- MGF, the mask generation function

Inputs:
- pkS, server public key
- msg, message to be signed, an octet string
- sig, message signature, an octet string of length k

Outputs:
- valid, a boolean value that is true if the signature is valid, and false otherwise

Steps:
1. Output RSASSA-PSS-VERIFY(pkS, msg, sig) with H and MGF as defined in the parameters.
~~~

## Partially-Blind Key Augmentation

To implement partially blinded signatures, public auxiliary information is used
to augment the public and private keys used during the signature verification.
This section describes how clients and servers augment a public key pair `(pkS, skS)`
using information `aux` and tweak `tweak`.

~~~
rsassa_pss_augment_public_key(pkS = (n, e), tweak, aux)

Parameters:
- H, a cryptographic hash function
- l, H output truncation length

Inputs:
- pkS, server public key (n, e)
- tweak, Public key tweak
- aux, public auxiliary information, an octet string

Steps:
1. c = H(aux || tweak)[0:l]
2. t = OS2IP(c)
3. e_aug = 2 * t + 1
4. return (n, e_aug)
~~~

~~~
rsassa_pss_augment_private_key(skS = (n, d), tweak, aux)

Parameters:
- H, a cryptographic hash function
- l, H output truncation length

Inputs:
- skS, server private key (n, d)
- tweak, Public key tweak
- aux, public auxiliary information, an octet string

Steps:
1. c = H(aux || tweak)[0:l]
2. t = OS2IP(c)
3. e_aug = 2 * t + 1
4. d_aug = inverse_mod(e_aug, phi(n))
5. return (n, d_aug)
~~~

### Tweak Generation

The augmentation function defined above computes the following value for each
auxiliary input:

~~~
   augment(aux, tweak) = (2 * H_l(aux || tweak)) + 1
~~~

where `H\_l` is `H` truncated to `l` bytes. Let `f(aux)` denote shorthand for
`augment(aux, tweak)`, where `tweak` is implicit from context. This function MUST
be collision resistant and deterministic. Moreover, it must generate outputs that are
relatively prime to one another. Specifically, let `p\_k(x)` denote the k-th largest
prime factor of input `x`, and let `k(x)` denote the number of prime factors for
input `x`. The augmentation function MUST satisfy the following condition:

For all distinct `aux\_i` and `aux\_j` that belong to the set of auxiliary information
elements, there must exists a prime factor `p\k(f(aux\_i))` that does not divide
`f(aux\_j)` and is also relatively prime to `\lambda(n)`, the Carmichael function of
RSA modulus n.

In other words, each output of `f` must have at least one prime factor that foes not
appear in all other outputs of `f`. To ensure this, the server must check that its
given tweak produces such outputs for all possible auxiliary information inputs.
The following Python-like code presents an algorithm for finding a tweak suitable
for a given set of auxiliary information elements, denoted `C`.

~~~
def augment(aux, H, tweak):
    return (2 * H(aux + tweak)) + 1

def prime_factors(n):
    factors = []
    factor = 1
    i = 3

    if n % 2 == 0:
        factors.append(2)

    while i <= (n / i):
        if n % i == 0:
            factor = int(i)
            factors.append(factor)
            while n % i == 0:
                n = n / i
        else:
            i += 1

    if factor < n:
        factor = int(n)
    factors.append(factor)

    return factors

def find_augmenter(C, H, L):
    '''
    For all c_i, c_j such that c_i != cj:
    1. The largest prime factor of f(c_i) must not divide f(c_j)
    2. f(c_i) must be relatively prime to L = \lambda = 2((p-1)/2)((q-1)/2)
    '''
    def is_valid_tweak(s, C, H, L):
        augmented = [augment(c, H, s) for c in C]
        for fci in augmented:
            if not math.gcd(fci, L) == 1:
                return False
            for fcj in augmented:
                if fci != fcj:
                    unique_factor = False
                    for pki in prime_factors(fci):
                        if (fcj % pki) != 0:
                            unique_factor = True
                            break
                    if not unique_factor:
                        return False
        return True

    while True:
        s = os.urandom(32)
        if is_valid_tweak(s, C, H, L):
            return s
~~~

## Encoding Options {#pss-options}

The RSASSA-PSS parameters are defined as in {{!RFC8230}}. Implementations MUST support
PS384-encoding, using SHA-384 as hash function for the message and mask generation
function with a 48-byte salt.

The RSA-PSS encoding functions take the following optional parameterss:

- Hash: hash function (hLen denotes the length in octets of the hash function output)
- MGF: mask generation function
- sLen: intended length in octets of the salt

The blinded functions above are orthogonal to the choice of these options.

# Public Key Certification {#cert-oid}

If the server public key is carried in an X.509 certificate, it MUST use the RSASSA-PSS 
OID {{!RFC5756}}. It MUST NOT use the rsaEncryption OID {{?RFC5280}}.

# Security Considerations {#sec-considerations}

## Timing Side Channels

rsabssa_sign_evaluate is functionally a remote procedure call for applying the RSA private
key operation. As such, side channel resistance is paramount to protect the private key
from exposure {{RemoteTiming}}. Implementations MUST include side channel attack mitigations,
such as RSA blinding, to avoid leaking information about the private key through timing
side channels.

## Message Robustness

An essential property of blind signature schemes is that signer learns nothing of the message
being signed. In some circumstances, this may raise concerns of arbitrary signing oracles. Applications
using blind signature schemes should take precautions to ensure that such oracles do not cause
cross-protocol attacks. This can be done, for example, by keeping blind signature keys distinct
from signature keys used for other protocols, such as TLS. 

An alternative solution to this problem of message blindness is to give signers proof that the
message being signed is well-structured. Depending on the application, zero knowledge proofs
could be useful for this purpose. Defining such a proof is out of scope for this document.

## Partial Blind Message Space

[[OPEN ISSUE: describe the criteria and provide sample code to search for the tweak]]

## Alternative RSA Encoding Functions

This document document uses PSS encoding as specified in {{!RFC3447}} for a number of
reasons. First, it is recommended in recent standards, including TLS 1.3 {{?RFC8446}},
X.509v3 {{?RFC4055}}, and even PKCS#1 itself. According to {{?RFC3447}}, "Although no
attacks are known against RSASSA-PKCS#1 v1.5, in the interest of increased robustness,
RSA-PSS is recommended for eventual adoption in new applications." While RSA-PSS is
more complex than RSASSA-PKCS#1 v1.5 encoding, ubiquity of RSA-PSS support influenced
the design decision in this draft, despite PKCS#1 v1.5 having equivalent security
properties for digital signatures {{?JKM18=DOI.10.1145/3243734.3243798}}

Full Domain Hash (FDH) {{RSA-FDH}} encoding is also possible, and this variant has
equivalent security to PSS {{?KK18=DOI.10.1007/s00145-017-9257-9}}. However, FDH is
less standard and not used widely in related technologies. Moreover, FDH is
deterministic, whereas PSS is probabilistic.

## Alternative Blind Signature Schemes

There are a number of blind signature protocols beyond RSA. This section summarizes these
at a high level, and discusses why an RSA-based variant was chosen for the basis of this
specification.

- Blind Schnorr {{?Sch01=DOI.10.1007/3-540-45600-7_1}}: This is a three-message protocol based on the classical Schnorr
signature scheme over elliptic curve groups. Although simple, the hardness problem upon
which this is based -- Random inhomogeneities in a Overdetermined Solvable system of linear
equations, or ROS -- can be broken in polynomial time when a small number of concurrent
signing sessions are invoked {{PolytimeROS}}. This can lead to signature forgeries in practice.
Signers can enforce concurrent sessions, though the limit (approximately 256) for reasonably
secure elliptic curve groups is small enough to make large-scale signature generation
prohibitive. In contrast, the variant in this specification has no such concurrency limit.
- Clause Blind Schnorr {{?FPS20=DOI.10.1007/978-3-030-45724-2_3}}: This is a three-message protocol
based on a variant of the blind Schnorr signature scheme. This variant of the protocol is not
known to be vulnerable to the attack in {{PolytimeROS}}, though the protocol is still new and
under consideration. In the future, this may be a candidate for future blind signatures based
on blind signatures. However, the three-message flow necessarily requires two round trips
between the client and server, which may be prohibitive for large-scale signature generation.
Further analysis and experimentation with this scheme is needed.
- BSA {{?Abe01=DOI.10.1007/3-540-44987-6_9}}: This is a three-message protocol based on elliptic
curve groups similar to blind Schnorr. It is also not known to be vulnerable to the ROS attack
in {{PolytimeROS}}. Kastner et al. {{KLRX20}} proved concurrent security with a polynomial number
of sessions. For similar reasons to the clause blind Schnorr scheme above, the additional
number of round trips requires further analysis and experimentation.
- Blind BLS {{BLS-Proposal}}: The Boneh-Lynn-Shacham {{?I-D.irtf-cfrg-bls-signature}} scheme can
incorporate message blinding when properly instantiated with Type III pairing group. This is a
two-message protocol similar to the RSA variant, though it requires pairing support, which is
not common in widely deployed cryptographic libraries backing protocols such as TLS. In contrast,
the specification in this document relies upon widely deployed cryptographic primitives.

## Post-Quantum Readiness

The blind signature scheme specified in this document is not post-quantum ready since it
is based on RSA. (Shor's polynomial-time factorization algorithm readily applies.)

# IANA Considerations

This document makes no IANA requests.

--- back

# Test Vectors

This section includes test vectors for the blind signature scheme defined in this document.
Each test vector specifies the following parameters:

- p, q, n, e, d: RSA private and public key parameters, each encoded as a hexadecimal string.
- msg: Messsage being signed, encoded as a hexadecimal string. Its hash is computed using the
  hash function identified by the 'hash' test vector parameter.
- blind\_inv: The generated blind integer inverse, encoded as hexadecimal strings.
- blinded\_message, evaluated\_message: The protocol values exchanged during the computation, encoded
  hexadecimal strings.
- sig: The message signature.

## Fully-Blind Test Vector

~~~
p = fd3af09447120e6b2aa75ff85a83423b2566d9fa900a81112a3597adbd7cac33
109c0144cebabcc2de5c65d9e4ad490ffaddaaf5485e3eee839a6e89bf32adef7efa
f50972a45a798d2f736baffb6b4184725222b35f78ddfe5c8c0a1a20468327f4b005
28686ebec6e488d03ae8aa135d67ed3ddf48f51eafcc262d26633a996aed844f8b9e
29e5942b461a49add651894a144a90d74cbec77d9690b385fb90b5eb62e2655f959b
f0a82ad86fd1ca7a5e99a0d181b770caad339e6ea6d766b323ea07d1a9206b93c33b
362dc2e700b45ede7be63eabda9b564aff3fec6ef3299713f45f77c0cff1456d43bb
08cb574a821c007fbbeeaa535480e2b6b1981ad7 
q = dee99acd6c0ffa549a23bb016bbe24e9bbf8287dd8152467d56b0b7ebce6d3db
bcc6bab1e5c82543dcfe4bf9f23593cd74a8cead8efb3ff884598f0da9493c41c88c
a9b2c22614b42d10c1438c602569a699beaae7c72d60bb020ba7ebd253bd633f98be
2db6ae70da8fab4ba3cee5c8347ce245a929087c1353ab9a7360aacac9f9470c5288
a41ecbe05066db9ba047d6f306de9e1a798f93c8324586cd65bf4a98945c68e16032
4943dd36281ef7efb18ca844346c8c76e605c801cd18721595083d162b53ad1801d1
fa24af8f9e887e7cd275d86d4a30bf42defe19b5d96fcb1286af25a9977e3fc52c50
3207b7986e7e135049c7749e790f5204ef66d1c5 
n = dc8030663466dcffba154e001e2481c9c9ad0b78f31ad1d016a46cb88892ef3f
73e892f26989258c9ee4efad7be1b224a599e47c0078f0ad37c2724c08f535e52409
aa73678c1e0a6ff38615388fd060dc4eacd5f9a702cfc27679d5639afb04eea4b355
0db66471faa3ac020ff75bdbcfa6536b2c976bbe1b893eed1d45622492b9ff94b882
8b582bd22330e74e7f3ad989b51435f57cbc4fffe8ec469dc42043e569400609f9cf
603088af4ba9694840585567bcb0f8741618348de659ffc3bdb5b523b2f5909011e0
7a6c60e86b7dd256976022e0e793542bdfb7c7744ecfa45b9ac0823d43d286899975
aaa207b7f1b04241a92f1ffc6e651139e48987475162f4fa2905b16ab0c419bc5720
bdc20499c36718029ead4a33fcd98154a3ad6e0a25ade8a059e27aefa9ac5404e657
e3fd46d5e3e7ce659c42c12bbfff7f9eed50d6b13a3a63fb52acbacbdb3de79720e6
9cb3c6b7ecfa16fa93c0109c7e5794d2b5195046342cf25c42048890003b09b69878
2b21736588392c96025edee5ffbb8ef6127a655b7f50e0368a3d964cc7adec743c92
6ef39acfb1c32a67a11fe7b6d3abed81daca61b94afec77fe6265c4964c0764c4c42
cd77fb70545341ec69fe9aa143139e0ec43bd5cefe8aab1a18800ba40a8ff5018d66
ef612d298fd8b3705261b080422d1beb139ac8ded9bf73b1103812417228d56faa99
42a02e73 
e = 010001 
d = 2045c2cfb2abbb7cd2477bfb186e4f70b14bda7a015ad38a9945c783dab966ba
eac4077de3646752858f0c655fd450b67c6661c2a46f0f0acb3672741e7b853fdc5e
6dcc2643a3c1f350b93731e81a9f929f113ce025498c0ef23832bb395bb40519a605
b4d4152f7977ab1d4228fa10d9fb860a11a4b7e8432f7b3e49227692d3c6d5597707
e44d2b5cbe39d220f30e31f8adc01f85a6940941735de19805b4933b68842e5e1769
fab21fcf484bab551fd5cdea38fbcde16fba6b36b998428eeb9d44bdccdb942501f8
d0f23bdcc89ec9c252b58765537f84ba472c26cd271bccfa7b53e1bc05c93257c156
2f7b3795fc91c7a0c49a591c212c39b13779c98aa8f6518e36f2f324d114c874c1af
6e85e13a2032cf1b714dedfc530bb810631e3c75444bc41cec0605ac4ffa27966bbc
b87f0ad985e4ee4da07746b8d77632d0b18b19dd8ac630164750daf025710b37cdec
06bdd17299dfa27bca10640f298b15a55245e32f05765df918d00ccbd8e6a02adc36
b1f8ec4c993c74c5f1197d9b398c9a745f643caa4bb16070642e36d5933637ebbc3a
df741030a71ec6a4b01245cc73e6a4c462bf6533edb029c5d17d25c79dad0822de2d
57d1010dd251ba79b6d80f53ec94fc78d8d082f80fa87f7409cbfec821222aa728bb
647eb89f41d46a995c229490864b695becd47dfdcbdb2a749accbfc9448cb1624b65
fcda1541 
msg = 2fc8fbb9c9c80879dd56928837c392f0d75c1edaa6299bf6ef2145bc4bb343
c177f23611e8169245b5906dc2c404accf 
blind_inv = 0eae52dc765ade16c4ec241dbcf43fb58da3821f7597bee5abb32e4b
2b47f44928fb2f0adac1b23b5bda94ab044a2fede8e30b899b10049a0ecfb99e5a41
04cb1a5ec30c2926d04764ee988e73664b5904c5654915d8b19b9de038bedbfc47e1
a64c444799a8017c462d574f52c5f1de53006e0fbfa37624cab501a015e38b792607
8e6c17c7026a0b48c2a2eb0fc4fb79465d1f1921181b9d8d3e27f22540b686334f13
e79bd6f79f2b804d636a780232cc5a28f15171d41c3899e281252c42b0c15efb22ff
f1be71e13eec441bc367dc015ce9426125158996f4ebfc8f7e8e00afde7e88cbd441
89794037051baaf7b2137937698b2ee2523851c274dde44cc5082a2e7771438cbb02
c13bb57e6a172cd25967a7c3d6da9cbacac60ec85b22a2cce8b78e51e0b3a5f549c4
76d5763c914ab6eb9f8261a6391169da56a924c12a86a4367b015f82c5ad3c5909ed
5a987f9aaa2d797a9f5bbec0f3d9b2622306d859be31939a15bb7e4c91efa7e7474c
a69dd9c1a7a6a382486ec95f78cb8ea724b3eaad0d5ba0a0f9654381ab9b9fe6e989
d612ac76f9e79e1ef1e893ac5692a2e7f20dda6bc4bd89f2f336bb4bc79ff3be7e15
da6cf349502f59834ec0fc7da9b8c53300580810f44ba05f044575ca81efa9388d85
bd37a98b2c5e916991a082340b3526dae99b0c10853b0f5b12b44fabb3460016ce57
6186dddcf045ca21 
blinded_message = 166f44a2057853b21faf095f53f5f25cdfd32453104507c39f
0a6311fd215bd34ba29d71d6d3d74d3249caf5f5f92addc7546354af257c7146b999
b1179527b62fbb6846330ff5cad8c9b1d6a134b7385807f1db8b19088108eca2e571
ec022ddf61fc57354593918009bfbfe3d290322b4f0ecd4d9a13b116c821115a83c7
16495567fb68209368ddd10023880a4eafe669013be36f5939550825bb167bc5f100
b9d323b0ba1fd359fdb9529df2b0f7337a17b9d513fcc42262f722f7611b709a9ca6
25f34edec99f8a834ac5660645a6d00a468a8ba79edc6ba20320343d3e778df2edd8
5389bfb6b45804c4c10f239edc30663fb412d260cdb019963a60226a8969b94483e4
e5bf6bfa62f2c0312a6313e9251b261676d9df3d85eb495071f8519ecf6e7ab40d06
20fdd548f8e95fe897296e4cbc85740f85897d17c6d33158f6d124c2d9507b6f0982
0955ca585a8316b594a3edd1426fa3be1232f48f726ea158252e54e9950c3faec389
839d57044aad951b2d17528769040fb1cde398d580402da6a9cab4982e3d13ae6a48
060f4eafff5695d135d534b5a6006a0ce0eac1995731dca94c5eb7c46b572dd16f35
752f0ae51829aad4d170e6be8099cd760bc6a1e17252d9b68a09fda1b1f8ab854ef0
83be5439cf8c83a01c7bc812bcc02c3e4b64d86040fdda3a1cb311dacd53a9ba0b56
e10ea27e50eca5f4ef794c 
evaluated_message = 60bad2d3ae36075186c80488ed927999779367f19c06f8f0
a26a994ccccc59aa7dad8d67de00288a36428ad948010d9e0cce53da1f152d004333
2aca5f299614ce58a122724f29f273975f03d08cd85a6d5cba1a56481e01bef9d9e2
39d1a9d8df2cda98a325c645678646d058a93d3dea2c93d986961811400b3b6d839c
1e9c5e6b1dc297bd1038e44cb75a0e29ac360511b4a258904d7eb40a810b7cd02499
1e786975d34c11b349428942ab71f966c0ce4104717c17faf211a79f58ca56538cbc
cdca4b7e4b4f61ae03c14523941639d738c9550065377c51bb9d85ab9c4c0d137f9d
3b5dcc6e392c014fa6d28ec7c5b3a8d0313f8a529dfe64879bbda2c741d9071391d2
61713f00c29c8271f6dabef0fe33a03896e284cae8558db9acd9c04842e79ca92c5a
b970618975a933eb40e0358e3daddbc32503a3f8dd1a9831c603cdd90e4d8fad892c
b352288da36c4b12178018d61590d82ed3cd6ce108aa5c400c3a70c4f7cc3ca9a98c
b63e2d135d436617727e58dfaafc93294945e1845be9be31d7a88319924818b65663
f2445d97206723f12d2768fb74fa01f23f8e9e351bc5d725111824d6b94b7e25881d
e5201e320522d6a18c91bb0b8215ca0658877ed5d0072ed6d46aba476a5108af85e2
b00c5211764065655e1c2765f29f5f5e12fd7bc7fd6fda55bde6c5a1740777ab3998
8ae3d2366c4df82828701d47 
sig = 35832cfa18f93454e234ab03da64ad6e817170997dc382b453acb5dd3a24fb
42140057eb373131b6a91ab9ce40112a143ddc6396b92e2707166928cb4329717829
b36f6aed24e8e46e62f1b5c513658df5320e18a9778de94c9ac9dc1c2732a74f547f
03d6bcc36124e1c03d48b47cd6b176fcea40c8a0c28cb8a84d42bc80cd06e0d733e5
e6639c4b6c3151c29b07115a24696064d3e3c1db00cf969b4fba7aa4c6e04f5472a9
ae6b44eba5a7f7b50e6bbcee9cad16eee6b9cd15dfe8772519a8eb3b331513db1358
c589db4a373206d3aedbb6797c4fce7706361b69a6b594e8721a6407839ae895bd60
a201614a9d0d105feb3c12afa551363a4cc8263a82977d54cbc5ddb6244ae68fd97e
a9b8ab01cbe4e8ef1eb948ec082d2c3dfd97b6bd8b6ab5130636cde02d3099f725d9
2aa2325e977a07a395c23f2dd4d2cc9b46033baace6a3ba03ab13dad54dffbc0372c
1ff9d0ca58c8eff29ceb11b06bd9eed4e12fc3a0956aae2a21317bf98cea548a3688
ebdef2328d7b8d7f6ff3197623efb9e93af2f5fc765b8c52839577cd8b6632aca9f0
43f10007d14bfa6de42454e9d852e857536249e9da7b69ade5b7196190a17642a754
11487fc454932704cd2fab0d16bb156ad756cf83392d5a44288018851802546097c3
9bad2a1a5a942fea624db7db083f62d853d61e98d1f7c57c702b698c914829393496
d678c63c13 
~~~

## Partially-Blind Test Vector

[[OPEN ISSUE: TODO]]
