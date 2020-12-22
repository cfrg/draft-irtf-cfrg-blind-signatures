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
  encoded_message, inv = Blind(pkS, msg, aux)

                      encoded_message
                        ---------->

       evaluated_message = Evaluate(skS, encoded_message, aux)

                     evaluated_message
                        <----------

  sig = Finalize(pkS, msg, aux, evaluated_message, inv)
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
- encoded_message, an octet string of length k
- inv, an octet string of length k

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
10. encoded_message = I2OSP(z, k)
11. inv = I2OSP(r_inv, k)
12. output encoded_message, inv
~~~

~~~
rsabssa_sign_evaluate(skS, encoded_message)

Parameters:
- k, the length in octets of the RSA modulus n

Inputs:
- encoded_message, encoded and blinded message to be signed, an octet string

Outputs:
- evaluated_message, an octet string of length k

Steps:
1. m = OS2IP(encoded_message)
2. s = RSASP1(skS, m)
3. evaluated_message = I2OSP(s, k)
4. output evaluated_message
~~~

~~~
rsabssa_sign_finalize(pkS, msg, evaluated_message, inv)

Inputs:
- pkS, server public key
- msg, message to be signed, an octet string
- evaluated_message, signed and blinded element, an octet string of length k
- inv, inverse of the blind, an octet string of length k

Outputs:
- sig, an octet string of length k

Errors:
- "invalid signature": Raised when the signature is invalid

Steps:
1. z = OS2IP(evaluated_message)
2. r_inv = OS2IP(inv)
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
- inv: The message blinding inverse, encoded as a hexadecimal string.
- encoded\_message, evaluated\_message: The protocol values exchanged during the computation,
  encoded hexadecimal strings.
- sig: The message signature.

## Fully-Blind Test Vector

~~~
p = bb0b6060cef83a7bdf29e8dccbb9725b98197dc4d3d868823db15dae41c0f318
5ca6469b7e3d308bd0a8085996a5b976d587f0eb7b562bc266f322d5cda111cf45e8
53051e617a1e06bc83da95b5e06e39bfddb09db66bc7108a4b838c459aac6866b7c1
27c2e829014025268978b0c57c63873dcf2b00241ad53abd89fe91713d139585eb8b
2ae1152e1addb4c3c95a4b8685836cdfdd29648f82f58c26f8cfa253518a7b7a11a1
f2b6ba4df4125ee1ff1171e9de5896948288d3b4953e0d527a48c3684b32823b7d59
f5d101537677cc5ed3ba9e117c37f3ad8e299462bc5792fb11b77ca14922666c1eea
90e6135a999077b009202a16a66ac954747c4bf1
q = b7f4e405d7e0236535f2722a48729ba7bb7386f761357ffe5bc0d29f273d3656
070f1b314c27f46f52cfa53f5405b67496d0ba38af2ff979ada23ea02ae54b2d5e98
6205ba214e365ac8acff3832ede50c2dfcb82c5d1fe505fa66569e6d682be1e2a487
2223d7fe78feb9a29a91ab078b2eaaa49aa8f9fb4311452d8cb22badd0ab1d387865
81c2b95f5c7e0519568be3a24a904322613342ca5677e8885a98c1fe61db9968ba6f
5999039a7fe6f5273c366b8b1532181168c068cb50274f9b4645dfad21046e8d8d83
e0053e504467ac94f053ca593cc575a0cc296575cb2486cdd188fc1dd4020ceb3a1c
a5873c88759ad8c41f6ddec2eb80ca4413371017
n = 86680f57770222618d237482601c4f969749a4d4fc17afb8c2aff67dd520e5bd
157b51cb2e8ef4ffd0b9ebd4e327619bc0914c66008449311cdfdc3d36d84a21b60b
91482463a7b2b093d7643b413649f6156b7474eb5428c5c5ecd5ea27f069e121f1c3
6e6e25df8ad0af6499083a4c4a148c69750ab842739aa336dc758f323e32418f47e7
b5e9fb281c3738e2a3e3b5523e471dae2ab2af23eaff6bf16f3b09ed9e22ea6e20ff
47f585df7135361de422d78818b18159fe285f4e6ff43cf913812f4045edf99b6b28
a1cfdfed278e522b00dfa56ebc8cb4bea5433c737e86f136d11debf2e352c03a2f6d
467bacfbf3096cdd60ccd504f236db06fc5a3e2cf6e428a5dc1ef291fb19e947cbec
d628b0754e987a5c15c9607ebd92341c9023f0db7023730e0bc1368ac589f6ba6561
87a8b6950c82a5421c7550d95e68256c0d5e53831747b1e9c434281f00943cc1bd6c
942e950950fd2d236e45c02dc8257ab9484a44699796a3f60a15cb1e4d80bcdc18f6
be8e134bf09bc9f3471b1413d0fa33d96e75e60bf61c9284ed3cd7c8d3762e428f1f
a3f4d46739b6e969599ce50cad8f2c0175c39572443d16dca52e41156c829e1d081b
dda9720c8907cee0ffdd8204653fc75797374b1634c28d12af365f73aa8d53a9a656
8889a590e19de468f464550881a3912942799837561ecc99559bcac8e1295e67f439
6fb0e2a7
e = 010001
d = 0aec3e02efaafebc4aca0cd7e393a96c2593588fee84c6450f9d593cd4ab3dc0
6614858b2b977695ab92d075969846b86fa7df3b92e32d478e7f2ad8d6b231241835
4c733e71d2d914bc8f0e983a2e7d484069612777507997c903fc4671447a764f59e4
75ff0198ef21127fec67dcc50268351904e8001d7663a4cbfa929b368c136d7c856d
713d38aa03d101107a1d314923c287c8f5b35bc4617eac790c7f11c97bc67ea2c08f
be7b578bd71969f277edd4f23c7f80719dd40e1ac3c2678a1e69ab3b5ff37d0b8263
e4f28dd22a1ac8d6b1d57b0e4ac86c8fe9c2531157c103ad5ec53dbd9977ca237063
430d1dfbc3be8a585b5b8a1c42caee75dce040992cb8c27dd88889e0ee6ff2b593b9
590aa04848685c4184309bec8b368203507984a5091945cfa42188bf4e7cca6c14ca
aa6190ec75911d9e5fd9750cf0e4ae734f64635286575e5c438ed08d9116997ce4bd
29bfc744bdea5f1a3b59cae6154eb69701e90f40bedd4bd894ee3fcdc120c7a4dfe0
a91a0e9daeb688f3ad6b96f181443eb3c1e11dcf3717cc2f46fb8a6822ce1ecf5456
814122b829910ea96783b0ca813601a8fe457ce80f5ea5762fcc0072ba23742f3c91
f74696537da0dffdd2b14830c7904e4f7b5c71c8e6d4c064650e78ae7bf76ff67b67
44ca309e64c4c640c7e3d02d2ebb9de2c744026a76a3383bceb36fddb46297cdabd4
a7c5d4c1
msg = 5260cac1931dcba8b20acdff25b6328dbb04e03c6fd96bd8bef7136092baa0
cc01c23173fbfd2a6aa17301ae30ca5d0b
inv = 5e8c230d264413d9d8714f1b9514f18cd8dfe09615b392ee6d62c8f4ad5947
db726ff1c3f9a7ad3f972b302ece5775a41a801a3e9133f3c167b9451c53455a5294
22091d9ef296e8b97cce3df302e2c9ec1a586a03b3c46596eff2664a06e13c17031e
97b95135f840c30a26fd74539f2bb58d7617d5743a7f1f989ecc79ea522af49f2c06
40eed99519ab52909f64c4aad4cf72433470a78d3af346973f286ffcbe3d2896fcbb
0c40f1be652b40ae5a17b87df480889980c4833b2612f87a8aa9d6c25c3a9758752a
6f500f6e10ccf1c97e7a7b321e1365f01cc5136bc4e13571563a1330db05dc98d327
51ed491df9c7523425061f175bc5da5180a5f4a59835636959c4c1e8fd66fa7afff3
56f3bc30030d03ff259d7192c559b570a1af54067ef92c42469f90873065e098f298
0f9e02f80a71236a3e78a85f79bd52f0a84e03d99af0241fe8eff4be80cc2d379181
1095e59b70a84164dcb93e5e4c389e4e88e7e404a39f217b55d0fb03de8b7b1ee16b
102eeb6f8a08eb543953880120b01cbeb34d4d889abf575dadbfbe8a54e205202531
61d2be5f900a1fefa2e7a3c53b6289783362fd5ad56109511e9a001c5afa9e9fd57f
1ac504f490a165f11015e98afc99d7b528271cc6319e98733faabb2675bf2debb60a
37c87a1328353758a67b8f8f7aedd89860abc9eb6a07deb8e65e76fc3cfde748d613
aa105d6d44
encoded_message = 542ae606a263b6077bc91a46134f3d6b38eab6c2b166402f6f
763f6575f895fa691c4331ecbe32035bb4ece478d3b003b58c4805aab4154f3844ea
3963a0b13aeac8bb54f43b7ba91d7d97edb4479b8ab0c4824e05de919c3d6e68c30e
937fbf87bbf174d4333b456fc599428d16edfc7798bece8fa6d7105b674cd6b9bb03
3c7856cfca01a098b56bb83c92530bdd2ac6f9666712b75bd292cdc684f348fc96fd
828b0283538ccf44e98f177ac9633cc29292734e724c5a859ad7d1e9225273cf31a1
4f7518672db2a95469e6f25a3c9a81b9c61da1af81ebf71ce0a1e1ca91d8e353d803
02a55ee5a69d460d80ede595b8d093ee459e0c64d8f1f1d37857b71617ffb660d3c7
ec37b16814d5263eb0918fd80e22e5fcb2c79faf938b91e753d800a580f58256777c
7122d128527c03415c0764bc19432e7c2e5c3aa605af4a94a8e67afb97b3063ff805
7e6d81a94a72c82aa4e073181656776513d10ddb691e98379c978668d5e48653f8f1
bc9cbc66ab3f8091e9a3032c45da4077736c00af6599e2ecf8fc1e4cfa116d558356
884277472852ae85ff839f53c2f6a49b34e334f4fb40b43c660e29e023d588eb369e
386b1e5ccd106f4a71beabd73583c726d27044f432e79ac17d79719311abc03a9738
95a2bfe6e9d7a412c82fcbdbb2df7306c9c2b0bd9460cba21c973373697c1fb63b29
c01c476b5eee6ff20964c0
evaluated_message = 48fe3e4367b4f1b18e8be87e47f06abe56d51092490f8155
41ab6acb9c301168716fe710240a7162de60d4bd08cdfe25aa14b5b30d6b80bd29a8
d730856df1ba568f993e58cc32a7ccccb1d60e99f25ae2559a23ea253b70b8ec777e
c39ba773ecdb8f76616b96f65ca7097e8126bf2c3557d8520d638f97ad9c84b1e5b5
94d802f59310ad490ab9441deea0d7fce04c60007c6221ff0276cb1422abb3d4fd43
89c3ac1c3d22760f114cbdc07e1b15e26bf460dd2fc2bda7b3a94c919dbab5dcffab
cbfcac9010594598c113becd753e490926176782fa21b12739672ad6fcace19eef34
d17a8f53c6de3d899fd96b313c087d4ad95ed30338ba9d66e04ebec0bcd759a5a4ae
e5f995b48b83a999e3e9d5ec45631637aa47681828f2d92e7ef3f5b00e58d6091e86
610cd12f05b145bce904b87990fc14feade28026f8ed809eb187a8a36144fcc04f4a
38371bff255e9a9c43c7102f83e00ea526611a1c578312663e9bcb3ba9cef7fcb47e
674c09b91de092215c2a77603fda6601c9c128b452bca364cad991004fc79520f530
ba6fd029ca36bc998aefa99b0dbcbc9317c19f7d895cf488ba07697b810270cabdce
d9120be6b00efec8ddd3d1a869d33af21409de1d74e82431dfa1290b9f0b156220d2
4b9bd54a2cf7e22ebb016678381147a0a45be8c655e992e2ee239cf30d15f2c484e3
4e9f2aac8770db17479c43d1
sig = 8124c651699d416828e97421cef69bda979bfe9b1ebe8a98cd0a710c4fb75f
b801d910f69bcef746419bc912c63526d9fa719b0d02354f9fd1252e0b86b780410a
ecb37ecc20d5612fcec8992783900c6212f9b899c18f30b38ab78b1d9670964cd7a8
1270b8f37a94b2c6902f49e2bf3c8dcb97259427a44483e4e1a14808f2ba305cdf8c
0b1d15c1ea4e274ed503bec759363c20f22fac5565df9d3a2d1af55c5e9b0ae35a6a
ad3dd48fc389a4d3a00d602be5abbdd55ac6161de90832e7b205dce258ef45085c61
20cbd5959055d0bf0f15366889a2c3aa3d3d6194ea261cdff17652a7b90f949f168a
8352b796424b93638ca545120ae7a9254067a8c0d5787b2b4e7c6a4468e06e6bdce0
21469f6a7007fd285181fa9060ed6ff39fa3d2d47a915fd20d392b857fd980ba6761
10f8802fbe8cbdd096c42f3a889ba75af87a23d25ef1ef22db2a1ed0a63b994153dd
b721e0e3ce52f5277fcf8bf94749087271f5522122bc18ae4ea33fdc6713208496d5
90b3b7525b06bcaf1ed0b05f4b3c5317af0bd421b67ce8ab10a83862cebcf014777f
42c2086b24033c5cd7a04cc9cc37e22d32447cee988de3072bf7d78e1002a129e97b
5c0fb699f57055196c1289c50012a0e0b1415febfdee72946b1137af512db5041f6a
02ba0ffe26485e3edf9927e83d96cbeae2dce79e5d37b0b26ea35264835d9c160e8c
3cfcbefafe
~~~

## Partially-Blind Test Vector

[[OPEN ISSUE: TODO]]
