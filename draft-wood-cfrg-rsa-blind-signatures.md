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

# Blind Signature Certificate Extension {#cert-oid}

[[OPEN ISSUE: we also need to convey the tweak somehow -- do we use an OID for that, too?]]

We define a new X.509 extension, BlindSignature, to be used in the certificate
when the certificate permits the usage of the corresponding public key for
the blind signature scheme described in this document. What follows is the
ASN.1 module for the BlindSignature certificate extension.

~~~~~~~~~~
    ext-BlindSignature EXTENSION  ::= {
        SYNTAX BlindSignature IDENTIFIED BY id-pe-BlindSignature
    }

    PrivacyPass ::= NULL

    id-pe-BlindSignature OBJECT IDENTIFIER ::=
        { id-pe TBD }
~~~~~~~~~~

The extension MUST be marked non-critical. (See Section 4.2 of {{!RFC5280}}.)

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
from signature keys used for other protocols, such as TLS. The certificate extension in {{cert-oid}}
is one such way to differentiate keys for blind signatures from other protocols.

An alternative solution to this problem of message blindness is to give signers proof that the
message being signed is well-structured. Depending on the application, zero knowledge proofs
could be useful for this purpose. Defining such a proof is out of scope for this document.

## Partial Blind Message Space

[[OPEN ISSUE: describe the criteria and provide sample code to search for the tweak]]

## Alternative RSA Encoding Functions

- RSA-PKCS1v1.5
- FDH

## Alternative Blind Signature Schemes

- Blind Schnorr
- Clause Blind Schnorr
- ABE (https://eprint.iacr.org/2020/1071.pdf)
- Blind BLS

# IANA Considerations

This document makes no IANA requests.

--- back

# Test Vectors

This section includes test vectors for the blind signature scheme defined in this document.
Each test vector specifies the following parameters:

- p, q, n, e, d: RSA private and public key parameters, each encoded as a hexadecimal string.
- msg: Messsage being signed, encoded as a hexadecimal string. Its hash is computed using the
  hash function identified by the 'hash' test vector parameter.
- blind, blind\_inv: The generated blind integer and its inverse, encoded as hexadecimal strings.
- blinded\_message, evaluated\_message: The protocol values exchanged during the computation, encoded
  hexadecimal strings.
- sig: The message signature.
- salt\_length, mgf, hash: The RSA-PSS parameters (see {{pss-options}}, where salt\_length is an integer
  value, MGF is a string identifying the MGF function used, and hash is the cryptographic hash function
  used for the PSS encoding function.

## Fully-Blind Test Vector

~~~
p = 0xe9663a2234c3f9536c8a1c9814877c6a33fceadca931b5bd66ce9504d74387
2dd344ab7082706ae77619054df3479b772a713c8f1cc790f4b608ac7dbef7aef29b
da5998f020c6a27ed6d4bc834a28616319c5cb20b0f306a05bf665e4099164da0d4c
58aa4710c94b12a499a1bfb8aea1e9e5f44dc78fe1050a86d332f8ca3536864bade8
07ba4956f67529093a1ead063ff29a1c0827e6dc18061d3f183de1c620c3412da9a0
d4acb7ddabc289720dd52a9a7cf9cde31ef8580ea752835b9a025e46da1817fa9b10
cea9807b9cf2d4957329cf1d40dbc9316d92621335ab897521235c2849c2644abdde
0023b893c03e2d8a30c525da0512b6c8a41f078098ca9a668c7240bbec63e0a88620
2067b0190317aa17c4bea07df3881d7cc6c4a23c880a7ef3a7d0a25854ac86c5304d
c92eccb90c264c0434ca7953794925a177e32dd60cc8cfbbce4c4039cd367c5bd296
1c23077127678226a48d387b22cbc73436c831db57bc07674e777cc0c97db3a418fc
47bb703744e690ac02dda9aa8621e0428ff20b3a4715fe42a11fc47b3aeb590ef596
9a3e57e68fd8ee23f492f4d08079278636e54d90c1d67179bb8acb9ae96cf8676d98
ec90e68b9b3b655e1a3ba576c53ad12037eb4e53cda4956e6985450c08c1f638773a
957c383918e07b5e85001093efbe6498f4f363c75a7f4ef6ec49fd27f635742fbfdf
4f8083a3eb
q = 0x89bc3099397a3f5d3b3b5719356e6c7c74d670c5e6740504405372521d1aba
67bd28f201dfe1274396c029f3e6ae2635f83c7a4b8eadbf82d05d166486ef59ce6b
e8188ba399da6b4beac0afbf052c3d331daa64f0dde962892a5274999074ad631ef9
5551fd8a405e4934d4f97586ace498bcbb3006fea4ccdcc9ae511ebcef8ac0f2a3a4
1d3975dfd67e105a73927503c191975676728948d5f7fd4119d1502d2e5d703bcbb2
8705593d8631ec3db1df6a22ec615f65d57021e957936e1d2a56fd9a742a0d07793d
bca6bb194bcb2b1b048fb34451995a0670cc7e7283086724d02eeda762363f12c677
9a101d2908f611174d5db3015e8f456d43f3035ae0d17d7f12e27ef3dd790b186e6a
b8f0b80d4d0cab1533ecdcb9c80fe40780e37887c897424d348ac480fc4e14b4dac2
f0d2aa424509cb3a2c18701a173eb5a867fc5855bc4d8e362a6d7b5ec645dc4958d9
6483a22f9a6b2fb696313e1e1b0100bfacdd84f2a0fd2904e7f73850dafacd4a7087
a1b77e0913ab48610c42d60196ce2867808dc52fadf98a8ec13c586748f3bdd77015
399c18a5f2d129e2ca828c6c6dce215037385b2485d6489616848a317e7fb1d86070
fa01f72569d86286ad4aef776485f14a555f8372974c8defc7d07f5dcac0d2cf6fca
039343257335723fd4faf50c24051fcde3fadd55103468cefdf05df94fa95428d0e3
7d4818d93b
n = 0x7d93487ddcc2001d80b8409ff28c3ccae1abc5efdbefe016c606c5025fe4bf
9182228adaff15faaba4d62b2e156b9e1789908c29cfc70a9196cfc4dce5e83c0de1
99c1a14bc543457d7f7a4d361b8a48294375802cc398adf5b5e6535c70340684b57a
f90a890219283d987a2718b31419a5c2ca91287bf938b612e5c97a137e7d3feb1b78
3bbbedb63d87f262e0b1b63de264bc47fb7db5d0613b1fdfcac16735a67c96a04ed2
b30d75ee2e761cdaa6d8721dd3b721e4f77e6047fdd18a292b3e78f181e24622b848
24ed3f2ae74559afd991f29f3275af015ebc3542a50ad4c9f86883c31b5b52504898
f585b7e356f659d364cabc05ed7abae51c80669b5e24dc425ec3dcef953445564b9b
b965dd7d181ed35c982e2d66346fabd233f00d383ea48307e697fe9e77c37f2a84df
f3436a4e2a36ebe644a209d0b7ecb0198d068e4ff29e4993044d9cd810737a58f0c5
a652b980ad6382be7dc152ea5cabd43ae3ce5e3b370c7c5e1e211d89f7d008eb675f
a76fe83675306ce6b95f056568f22e1f8bf374ae5bdf729f9959d25209d49201cf3d
aa2d00d2b5b7826bddb5fe64326a7b301908412c625a6adecc1708a47def5f77f043
957162a59dc3a1176cea2eb4806315f73354aec50e772b3c908648dd775823400e7b
6b66f22cb73fd16a20b779e960299235bf177107a58e3d58cb5fe55bbd443593d495
c647a84acce77c87189ec45f0393a09292abe09dfdb902dc4fe0642e6a9f46be7153
fe8f9e5c41093e370b60755ff94ceda1bb72e7ecec7e4c353b118ac249bafc2dc0e9
4767c4c0caad754842eba1bcf5aed5f1dbaa0dee2094f5bf66b3ab0199decee6bf36
ea46f1407e1461475c3be9c7ef0b4c9b057051ef39875c12678d40cca3af96e20a59
5458effcb8b5f782ab90f5db2d8b3f48f204600537c2b9a4bed2393f23f2bca8b846
0c5ede11c30883f255e437bc995673a93acf902baefd1f92223d50e3a7222a832162
a331fe38c615db3e2e080dd5efd55a06c04ce8e8c37671d501ce3997341e78aaae1b
99489aada18f801461a498b02e0d2c0812f3e8f6d309c0a4f1dd6e4695ee9508d5ef
92c0e26c036b675f4bbe8bab2448b894088033f53b2a5dca832070cae37692d952fc
1ec96138636142e61bc737c8420a2bb0776cd16a9bc9b42f793f1e2b2d115aa61682
412d77c37fab41b4c33fce3fe039b1c2fb72eaac29f34d905165ea073b061227ce9c
52512fc9deb9792d48c62a9138bf8f384e4694b1bd7bd4159b2b9d8798fd7ba22a31
1264397e3bf4fb0080edbf3024c5ab36c1d84d9240673b10379ea7a175f31fc0a8ad
93a574a62833b33c1b7f29b6f077e9069bbc00697b225bf9f46200db76a96fa98c44
4561438eb4371ab77d3eb0549aa1decf5b9f3849f5d469f2cd8647da8d24adb08052
ac5872aa50fa29
e = 0x754a0e967faff7a292c25d9b4a68f35334a2ae54843a3b66a6ab397b6e9011
db7bf683247172959b9bfae922e06b80eff295e1d8b0ffc83f7d075d5047d05c0213
a0224ef80534dfb2dc08a44855c84c0c19e6100ceb477aa916a49b3024eb90e1d3f3
9e4efd9315d772f3e238258e08ea3bb15a5338bcf9201fe1627acd66864ee9a1680e
babac5698b18ca2469dae9f719288f77a226c00e87bcc66dfb0ecd3d5cc47927ff00
20c2119b4343c0d1d0d3716f4634fa793effc264d8e849127dac91fe9ddef323a4da
0760a0bb8d114eb689c4b16b08827c69465a501f07cd75136b79dd1b39112ed6db51
e0c81edd345f8130fc2bc24f2840e53b8eeab95f840fe66239bcd0d7cdf19b6649aa
0ee0699aa9e93ef0d5de848d354e6087a01a77d75d0beb4fcca467a73d2ab07c28a2
719eec86ccebd9f35fd29b43131be54b51835d92d939b1f5d8e6cb00066fcf40bfc9
e1dcd852fde41b9530afe9f8b3e9f9fe2a9c156b5cbfdeb423e333d7b8e526bb071d
e97aae8a31323b75d0530a52a1b9fb12c7d2674156858c2d7e85e85217e53bf0db48
869d45028d6e74aacfd32e229b17ae4a43c84c49d36d35593d9cd90661969df2854d
6183e602a48b33ad4718dbdaab4c37200b2c710e51343368b647709a9169c181cbe0
e7084a4e6dee8db669b7a21b9a9d26e07b19392b60d10663aadc4c88b2a2b176210f
b7d67ae07dacd40bbd56b05a4443df173f30090fb28432a8e95fddd018333ae54667
960e29d115df9f022d0725e989b421c9cc8141fbd1d3281c2ddff8156f69a0b995e9
f9ec04da70cc81e4099fb663d69127850ea6db0bc03c1854e9cd202a6808caa34d11
9683d086131a0728cc74d4885b58c99e3ebf068e9c78be4e50c2e76dc0edae9e5fcc
fa945be2a4a8f727c4d37da8e5e77351fcab7e4ca631fe5cee19f9ef7f15da263284
66b40dcda624856b2c13511e2f71d9f4c55bdae352783973f221e4335ce2418de4f3
3ddce1fd29a165c790849aa2266b5395eaf679ac6f0aefa10c89295af677c09c28fa
611741c2d5a051e2e6449807e95e387523d1eb1f8f2c23e6a4f24f12dd4e557af8fb
dbb4088df670d582d70fdc44bb1a471a59ffe00bab755f1fa17572005555fbac09bf
bb295c86ea147b005f79058e0fd78949f14e0a053d71c274fdd5eceb1b848cb22c55
25ca10e03f7e5004c63a4484363f6035111fc053d2e224c194527f44488e18983aaa
c541ac54dad131df79424c3dfbb4d42e19ee09c1ec5e0f99b6d815c43b2e283e8899
ff8b9f17f840d7e28a3be22eb590fcd408a30b851ba6738991f664ae1c9090e4515c
10e5290522640803bccb09e3917d6aced52859813ff94e12bb9e0e8667bbec315ad2
291e9d01051ab552f7a8fda871036761ead4e7ed9262842a0054043e3bb01d5699fe
03d845a56c3895
d = 0x61d0a75ef00a0b164ebbb47a160cf669b3a7e7bc86fd2aa7839bbaa9b95cff
30d1fa87f0c8f35c6cc1e8da2e52802a9b13aa326905b29e6bac1c86d5889beaff8a
4f3219517df757b59718879d6b9f916e0214908dc83db2a8923e55e690336f6d64cc
10fd73438768d932cc0acff67b2462a948647771cb0b9cbb014f7079900d94c7aa73
60cd720afd63d5cef55e1c46a3e2f5c3ace4c97a3df9ba2850107b69c155b931c1af
5c88174ecc7201f9679f2e6d604196e0a6fc63cc9446db25441bf3a7ab8d34cbf666
eebaa115e3fc17b4c35f580c98b67e4bf32646c4be132f040d0c971aaac7b7b98e6e
18bb382db2b2ef5e13cffa68c94ff3bfab26b9b45f853f723f559f6f50bdd2c2c51e
a360e2f112c1c25a6a2c4a6727b6254903072b86c7e0d5add73a0d649df1cdcaa566
8c551b4cc4a36197b5343e9bb035c7322b32329a07226b84d8996984805ac4f1a2d9
bb0fd078941bfc5fedf3cd0200a7a40fb466e5f99e7825a12c1a1883975ed9d1b1c3
85453f9847b972ed39ab161d0225a5e0c022f6e29c92e1a7e2b9871b26171b4fa8cd
85a0e41c48f4f08da0f60a3a11de27909e4878f2a52e21f90e1250f0ce45864abac1
1e562b355af8e661ff4c827e5c549a08a1b2218c3450f32e05fbca93cbefc81e21c1
41934d2d5473c4a26a4f95815ca08b6c76cefd09cc598ac07f34372032fc10fa1ddb
9ee88ac5019303d7699b9ea45b42cd096e54d0c3303d64902ab0ccdc403ce6b81b53
cf03eddc7cc6556ea4ef10cdb49a3071c2046b6be9a7522df09406f76ff573426ce0
fa545d26bc6744fbc7d9869fb1bddd193df04963268031f965e934e57fd4b683adfc
d23958b899acd7b023b77812eecce1661b9dfb235a52294b7fcdabbff1c7724e0aaa
15caecd7923fe2e14a81c29183ad30813848e88679ee2ed2e5b9d355e8129a3588ea
f7ecab2b6500c3486b5a90c91baa08b75eaceda617bbdcea4debdc0df3f3699166a1
81959c501978bc5aeef13c7d0e54d715f9958a021297e64f892b1f7a93e550a06344
21591adaee8c42faca809cb682c517e49da7f96ee35403f93d5a2c2a3a17d52af89d
cca32febac78c70cd89bd42b1c0b87e7809b12d8b687bb4c46d3abfe61b3678e319d
574c97612e942010b9eacbe4ab24be75f5d303d0248d22ccfbdc0f21df7567c8d27e
3cebb47afdae0edfaf7e3f8ff7605d756999a24ca6705f5477bd22f9335f7c45cb31
22d25386f45dbcb038568a58b2bc111e65b706db356aaa7ed1cf230c0f9dc7ea611d
9db49b8e17a6ed135adb3b061934558470d63e69ccd73ccdac4e0171349e431bcb05
9f7aa0c816489cd4aef4c1e2c013dfe98e428b4dd43550d2fe8fb5ad3097539c90a6
4f72de0ef9eceff04b23cc7390594135b508730f0d12506c1ce1706a2762210a60e4
8e5bc28d8f7209
msg = 0x68656c6c6f20776f726c64
blind = 0x6901112e4b451382ed179abbd6dc7557c6c7441d3d41fce6aa84e18440
6430f70ce01d96cc3244e83c2a549ce20fcbbedb67df7f72113ad69c329f2a442c8d
4d9f1454a9fccdbc6f9c98563fb067ef0a3a8dbbdaf57fc3025d05d993d7c3aa9339
98c9002b1c804d5f4463ef8d2f098f82fcface44f8d2eead7fd792eb3ab2e318128a
aa37af355b463cbe597259f3e17fae5a33ebd8bfb4ccf5fddd537da3692afe6bfd0c
0375848001e49ecfccc2d0f51a0ef20d59099f6b8b7f37c0987af2f264873916b8d6
48ad04df69ad18b9842240e23506d540057bef5615e2ac7bfd606c4dde353eec6d44
0587143fad86fdf5fa93e2c170d2960f1603336e6035ff914cb95bb1305e388938a2
ef5b11c3b77e447aa459336dddc2ac84c8cb53c481d467702199f1bd01d2491ed93d
fad63f5df9adda014a0911a50ecf03887a5ccff4ad457a6b66e4356bd1f6333a596b
6752b8cf4283437c2ae776fd8491fb17d0aca66a2b09f51625b32ec2cf4e43dff0a5
fd1b1d767ab7f848d95f411c70572d240d7b5c44578b2cfae83bce75ed1b450260ab
08a4adb36f867f4be1459a436d028fb8bdafa5eb9d861b528b0a79e00871a98d943e
41084343016d55402d33d9a59592fbea05f980177cf6190412d41dae527977afc8dd
8793716343d67b113cf1ed4ee3d3c545879f467796803dc32fb89510e5646eebcab4
63bf3c9e0abf4e13a8dfdc45f07ab934b77d1fa7cda90517cd218a296eff5d8cab13
b5a4cdb57587e4f1cc7039bf6633a7f017a41d55bb07281aafec9f21c54c072c87db
bda2662809c3eec1de9fc5e304af6408e5fb660b378e22761dcc18e3edfe8450c3c6
c19d7ed641c2a2d84a3edadac7b66beafcac5550a8231beed6f71abce82e637f3170
807d63404628e195dd3d0d73fc63dfdf6133148236683de4f9f7134e1d87bb7d4dd4
fb1cec45be710956eae54899e124c000ab600d882c18725ee34138eba9bdcb050871
b693972cd6041a03f240a05274b087b786d69837d458d20513a9e277f5bb8cd22900
0058175ea90072d5acf1bdff33edf6fd9743b673281693607f57b71244caef90b70b
c4d6c8727011ac8348b747cffafd096329404dffbe0e0e7f3a3c67b08bf18eeaf626
eeb784662d01d4d9b4390916d29f9c4f3cfcda1fe76eb9b87168f5ff1bbaf1f55686
cafa1a99212b23ec3b003e7499e69d91676b06767b115e4832497f8e80362e699788
52573fae4394373f62d256cbca72ef946197281236e17cdf5dfbfe091487f170708d
1045f9892f9ba83479e3b5f3b967e3a9a378bc35d6851d63cb7ea7ec4716f03ebedd
894ce5ef725de33f313c7556ab5e4ae99931889cc0f75c5d68263bc4a1c5d8d78266
57546702e5f4298438f29059051a469c0ae1827f3b22c96dd017539cd5afb60c1d49
142064491c7e58207c
blind_inv = 0x398e72e65d00115c643243fc1210bd9aa7209ea3e59e70c7009e34
3552e66203b2b37179e6c537ea138762f0164d0e045130d28a7950057cd3a687bc12
be9755db0896c89601644f534e7a27ff72cfad0481cd73d6598db02ae6902dcedd26
ac6025c0b8bb212c7b617ff0c62f0cf03bb298fc614e05d3dd80e9111a28c87ec81c
2fc8737c21c3a261f026ab7adb822aebfff34ba3e543f5f7a5b5c87ae35f31ab2992
3cf50e64ffc2d8ad2dc6a0038e0c28da4d53d75ea9d25c135fcaebca111189f3f922
763f345b059b595aede48077a191a771d20b315b1e946af2ca573a1d5ac9d0c5c078
69e660169175cab1980f53153f1bf89eeaad8e2d29d85399ea6a9299b292fa2a1136
467607e16a00a8330ae2fe18a5e13754b4f808d446d6acb11dc24022e9257661ec99
b202d0593a81f5dd85f918b0f4753d81aeb9b3dec034d67359908731dded7e0aa226
70a7e0047c0c6d33fc5675ef9dce65499fe5559d98114f3485bacb9acd6c6f7dd37c
416faf289d93b8712f4183622ade609a5f6b95696334abbb6f63cd20fdf478e8a344
bc514c999a910ca7d9f75c28aa135e3925563d3bab815c0ff168557bb0879a039539
b63d8f54e4b7a80ad5808439f2a78db8944acfe1837d9a458da4c930741a601d4398
4b840f1aa7edb7629c229b517be810e78c3b34269a35cfdb1989c1312ab5e4a93f03
50d9eeb6d25c564fc933d950f564e26ed59b81d0813d6e8807a244cb59c6bc32643a
fd3e8c5ce847ba5acc6d02e9aef1d61c0031240ce01612d73101d34022648e239d84
aa9b855772fd82bb326f8a704d03f7fc2aecc3b34db4cb98b4c775108eea36d2c84d
ece92a6646a7689efb384d00b159ddad92085b8722425ba2da57959f06a96b1f9656
a837b939eb2cb4a08e3d88c98425e400db050c06f9d1f978ee91110b3cae5955d18a
c552e17f40ea4037ca23614d65d973877e8cea99d9d2dfd4a4289a0c62ef05db2867
4f34bc99bd8278dd26292f93e09e5d800164134fc372cf38a3856758d4d74e98b4d0
cd9e128fdc3ead7af49f5211a843288a6a3b7b65e26582bd40227a0be5b253910703
ae542b36847f3567f4e69a020a2cdf337bd62a02daafb7908f34e1c2bbc495edb9a7
26bb5d7c78b1632a056b4cc34be989c8d2e1a0dcc146dff72e0714b4a10d0fa39aac
07cecb8dfe7243cf94d16f396b310ad4198c9f89f8bab90f8885b3a7f77ed71866f4
04b15281a5b868b875b359df962108d71447b1836a675b3eaba2b2f7e4f39ad9aa1a
b93e748a00b1a02a4ef5d724cb772e03793b3d1f8360905ddd659b59a5f3dea4eb0b
0a1e3a0356009b0646530dbb5163e53395a47e7095a369ed941e2c746048f696ec94
d4c8b4a8e8069d33c122ce2e97ac2d42d9c968ea0fec869d962bb64188d1f39c8dc4
5e2ec2b3c5888e1ec6f3a0
blinded_message = 0x793a34e9358f4349ecb7cec2ac0cf00864847ae2936f8b58
166921870dc8cf1b13b1dbb73c92efe7b40357e4a5b056fdc67de63886d65ecfdca7
aa6eeb9be1cb77584b732096a0cb9331b5db5d1ee4f591c495b22df6a5e221f12f42
c5f6351135f4a0935c987d3a9845ce88ca3bf827f13991fa0625d591ff4c463fc689
346e1bbf42930570b40673371e9063d250c41528f727360ed1addab2f55e02abd662
1dbca7ade93aa785b5bbe6f4744cd5c9598e0799e7071d4c1b582880b6dbe40ae93e
5e93d3082c76940c4e7712505498a9a59a4067ed784942ac090c671b6dd5d1de2fcc
ecec7e50dfc861d0902bc578e405cb12098cdd601958605e1d452edba01eda4d6084
b30254c9c37138c5dba0e383762a1c10a3b68c451a5de77aaaf68332369754dd49fd
681bb1f42c14c68c4ed5ea0899a32dbee61c7b32edabc8d3bbc3ee17a5638d96459b
7f60cf7fbca4ceee2a94f8f64d3823186f4832f823bd6970dc1fc82929aa5719c01e
3fcead953b64c0a6a5dd8e2af27189fa343954e4883390a936bd9ebddc8849dde8ec
f7a619073a766454141f4faf18d56005855563ab45ff32c2817841aafb6560e0905e
96646e76f5c098204d1739b8f8b2223b00477380f399922b57ecd1bd9e96895bbfc7
4f7d5a437046d2f0a4ad9dc0777aba7d8ae3e21a35e348d37aad081c25316afd58bc
0a92ea04bd59630aed0116bb0e4d382ecd487d52e6497e5359118de13ed32d82554d
b148831a69835faf3be314b219340c85d72815b85904935d425fa6512985752827c4
1b16fba026234f4810d0d272806d72590eb1298ee426cb0e82cbf8d422aec9828269
414998ded1152b506e5aeb7c9c351224da600b1f74a9240666187dfa5ea94649ab10
875cdffd0c973cf3969a20fa2a43266e2fb21501a8273746e7bc42bffd16f0d51acf
e8d36bd944fd9c2478d34da0af40d89d24e6caae062b58b68431c352ab4ffa4eb1ac
9f4f142d3c8800191889078e06e60823a3f98b9ca189f4c373a8e93c09e76e57f110
bcb2b6fff745d60a13e78b55c4dba8786e2fb496f1e3ee0345e3a855420ff5e18f01
639bbd0858d579dafc363dbc1d02dbebc4efcf32702ed0da5bae570e2dd3773abc52
8afa3df3f9ff582d57d1ee5a587ef4b2f13408e3af17abd022cd858e2509ced45427
9919fb48514e63aba1bcc3ee2699b176fcf5a3fb69efd36ce152ca8587dc3d87d643
c72374f2c77e35d5ba53d36631d3624f97dd2a5cd8c335c4145d91e90662cf518ac5
235616a83a8213611b5ea878c84efdd26eb1ab04e427b1f1fc4dcbeed3ec545a9a8b
63547ccc401ae3d9056e6ede1e622342f9b98dee7cb9f7d53f299a1472952128acd8
36e13fd0cab403b5c0e424f2f31ebc40ea21330b0ce8f786c7022f370c1d76b63309
4af462c050f94f26686d91cc46f1
evaluated_message = 0x793d34e6e914df876a8dd285259507e1060c4292076a68
5b602fee720224e69fc9ae6284c3b676caa2e4bb212525c52ca7fbb976a5d4f94662
c8018da6363d28fb7b4ef39b028429bed3060054640f1d89d1249458e3aabe44cd86
92661ec1e354a50735e3ebd8bcb345d973620639ddc7a166dcba6fe50b8562eafb21
b7d93965d965fcbfb1bea260096cbe109d88878ad97baab749d8c814dee081577e6a
d96e88870dc66f51d8f299303ffacc454f5e6fd3c710d797026e2ad9e6a1c9c7edb4
ac5e5e4bf33b5fff7bcb5305d73577abdc29461d17f6ef371091f43343abc259af35
5536f2f594c060ad7be820842d8275e571bde57c9f00b8d04089a0094e157d867e31
9bb0b52347805b170633c3f5a50d669a3a8bd2eb7e8af93e75e01b5e98c26034ab4c
a82c7641f00c6bb2f8ee30dabf119e72aa78b5c9c0a79350b0379b4193951d43d6d7
5dbe788f0373db3ede571a86de6f3821edf51a0f082bf786cd61e8aafd77a9ee8bea
b5e5b093e35384db12fb223918004413b6c9117fb9cb559391bd42d4d12df3bc8d15
6e74dec4c9a52c5493339a4de5529eb4094145d42324dd00a0bdf365921e5fdf06da
82030ff386247a184a5db169295910efd38f2d251b07aeb70a9c3b0b69ef1e973f5c
f62850ed5d8b0404adff73bfde7d49808a85f8ae2f3ff14ca1d1fce6987a4543e980
eabb0faf78a36c8b595bd363791d42c5fedfcf1c616ac9dd78beead7d9f97883f096
d10ad31981b50b1438b2dd01a18b73c8f8f4e14d82c0e5db90e4de4460d4b1e61e96
df76ac2d5e12c2c016d918211bd16df4385597c70ef3f80a92b4691d475ccf895e76
f3ca70d47d89710f3e5182b7abcfaa7928421385e2106dceef6a07b40cd15af2d659
40ad11491cb951c298284eddb32ce7676157f8489c49536c1347e12f562004d6025a
bffbb0f601c76c51319350cb9134f63d8a02326bf44c4f41fc6b34f8d9b57161fb06
cc5256a89df2107b0b8a138a9f8bee524ff0fd329a7a06af96157f684116b9f7354f
8264e68066385881338420f3dbceda520882935ea740691b6413ed7496a8321b83c9
3f24e937f7db44e55ce88872ac89f02f4ca35aa1bc35b38d2a598b1dd2c63d274686
c1813aba40b7025ff3b9743194621bdc6e9c36c7ad716666545cb44f93671aa309dd
37a07a5c9c5c97ebab132fc0abe30f5bc23e9749555b7b2ec96748ffef89353ff723
4af44acd5395775db317d88d036b05c39f9b60692a68b9c72298d372e0fb9c09ffec
356cb0d3d55c1c631032ba466c02ebd63b10085a545a44c5bf686b69d160f1c0a2e3
b38bd1618a3598d0166394cae6580282c6024381831a9c5d689365340b16d17e2caf
77a85d766c455afaab9182600532945ba4354b21d01a1d6d1088dcaaa280878af0bc
0c99232d3f6bfbac6384e3b38461f5
sig = 0x1e2e9b8e20edd0dfc067f716e6ea4914a14617115a259fab1d089de23300
4364265dc8ec2f0564d0a7648457d6ba6c4c967380afe1122347cb874fa25f27640f
280fd5ade8f3b403e8f74f0f5f42280f2cc75a1d9d11812911e659004709fd66b874
06f7e299db5eb5f46caf0aae7d61c813b081814eef19aeba75c9efaae364580f1478
b93edae702b3792baf1046203ed035a54e3d0942fa18d98b7495983d0e93c51c12e9
d7c3965b4314acef97baecaa2cfe1f1a3396b1af2de9213c21087a6f120b9f45fa5d
99fe4fd82574dfd275b1cf928be26c6be64b0cbb38f623eb8a347730ab638d3ea744
02548b83a608320d9f9814a647685676f9dcae1aeed5b493440c378dcf6929defde0
64a8435c95d24f1e68107bb04f5866dd0a6d76f9cf05cf876f71a32402e99b0669e1
e84e02b058694f26e3a80708a1d690ad7ee9925435066251e7a43fc6690cfe6af00b
dabe518f1513907c758b2c622dc4f60d743cc5857c2130d01fdd029d986b1b8431de
fdbaa6c7a22724a3a62e492c9305c89948aee3cb76b7da0ba240a25e0d2e2b6e6a97
b01e3331f38b2515d8563ebec67726ab5406396f09d923df65c581dd5a0367a8dc12
ac49b2c9f9db31b72261b649353f26e7f446f30cab2317ff97a55d3ae6f185006b4e
47597d53f2b437caf88d013315281acec7bd71a59d62f476b6043ca2a21b3c9e0c0f
5f1eca59400c975bbf1747030f3ba7c21e34335e146912135398a670abc358b3bcfd
3efb9f79b09d1f4ce0065e5f7908ee60b3a7f5b0999ac992042ac76173ff87e61734
f354b1ea7b2087f48f1a234efeac30f52c3acf8af8efb1ef632945a062f188a78441
a81f77af2298e0fa5afc3a4c02e11ec3e4181d9ad6e56296ea50b0c921fb3a9ada45
f93c36027828d89dc02b468dbe1f87dccd6e6974e7258dfe63fc9f4062223dd85d9a
147a1db4708b3a912a13733e6104eb8139125effea27895cd21d49636c906bde2367
397fe7c330d6c76c2be5d4cd21c8d25595e5d4a1f8d24a27aa24810d228b4ce512c9
769a8aaf541552b5263abd03fbcd679c3093b7052b1b751f800754a5112cf68cf189
8ce5c4bcf701431d6d18c3d933472f8b8b75c9637552f769dc888c331473a22247e3
600d1e0e6e8d99a8da9062134bcf866c4683dbfff207b7e93ba2aa4f807407f82bd0
033abc41c948e51e654bd192f07b5512fedc31507a8fac3929e9fd8d9e79225d01dc
75002c12afb771d6535799e9e0a4ee231b181f414bbb7ed4a91346d72a16260e1303
f3da789c6dde8e68a189d8e227c548f9741a6221af8e290ad1ea5e836c89d304c902
df7d25706ea69191f0309ba16d8af4ead7fc22f54452edb5fd05033d142e6dad2181
7b7469826a533fd9d6b06ff4c203c3379c9bdaa35a675738eb73cad847e005d2ebd7
633833af278d5953
salt_length = 0x00
mgf = MGF1
hash = SHA256
~~~

## Partially-Blind Test Vector

[[OPEN ISSUE: add me]]
