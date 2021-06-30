# sage -pip install pycryptodome

"""
RSA-PSS code was copied and modified from the Python Cryptography Toolkit, mirrored here: https://github.com/pycrypto/pycrypto
The code re-used below is in the public domain: https://github.com/pycrypto/pycrypto/blob/master/COPYRIGHT
"""

import os
import json
import math
import struct
import random

from Crypto.Util import number
from Crypto.Util.number import getRandomRange, inverse, ceil_div, long_to_bytes
from Crypto.Util.py3compat import bchr, bord
from Crypto.Hash import SHA384
from Crypto.Util.strxor import strxor

from collections import namedtuple

salt_length = int(SHA384.digest_size)


def is_coprime(x, y):
    return math.gcd(x, y) == 1


def is_prime(n):
    return number.isPrime(n)


def augment(c, H, s):
    return (2 * H(c + s)) + 1


def prime_factors(n):
    if is_prime(n):
        return [n]

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
    """
    For all c_i, c_j such that c_i != cj:
    1. The largest prime factor of f(c_i) must not divide f(c_j)
    2. f(c_i) must be relatively prime to L = \lambda = 2((p-1)/2)((q-1)/2)
    """

    def is_valid_tweak(s, C, H, L):
        augmented = [augment(c, H, s) for c in C]
        for fci in augmented:
            if not is_coprime(fci, L):
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

    attempt = 0
    while attempt < MAX_ATTEMPTS:
        s = os.urandom(AUGMENTER_LENGTH)
        if is_valid_tweak(s, C, H, L):
            return s
        attempt += 1

    raise Exception("Unable to find augmenter")


def hasher(x, l):
    assert l <= 32
    return int.from_bytes(SHA384.new(data=x).digest()[0:l], "big")


def random_integer_uniform(m, n):
    return getRandomRange(m, n)


def random_bytes(n):
    return os.urandom(n)


def inverse_mod(a, m):
    return inverse(a, m)


def I2OSP(val, length):
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError("bad I2OSP call: val=%d length=%d" % (val, length))
    ret = [0] * length
    val_ = val
    for idx in reversed(range(0, length)):
        ret[idx] = val_ & 0xFF
        val_ = val_ >> 8
    ret = struct.pack("=" + "B" * length, *ret)
    assert OS2IP(ret, True) == val
    return ret


def OS2IP(octets, skip_assert=False):
    ret = 0
    for octet in struct.unpack("=" + "B" * len(octets), octets):
        ret = ret << 8
        ret += octet
    if not skip_assert:
        assert octets == I2OSP(ret, len(octets))
    return ret


def bit_length(n):
    return int(number.size(n))


def byte_length(n):
    bits = int(number.size(n))
    return int(number.ceil_div(bits, int(8)))


PublicKey = namedtuple("PublicKey", "n e")
PrivateKey = namedtuple("PrivateKey", "n p q d")


def RSASP1(skS, m):
    s = pow(m, skS.d, skS.n)
    return s


def RSAVP1(pkS, s):
    m = pow(s, pkS.e, pkS.n)
    return m


def rsassa_pss_sign_encode(n, msg_hash):
    mgf = lambda x, y: MGF1(x, int(y), msg_hash)
    k_bits = int(number.size(n))
    return EMSA_PSS_ENCODE(msg_hash, k_bits - int(1), random_bytes, mgf, salt_length)


def rsassa_pss_sign_blind(pkS, msg_hash):
    """
    1. encoded_message = EMSA-PSS-ENCODE(msg, k_bits - 1)
    2. If EMSA-PSS-ENCODE outputs an error, output an error and stop.
    3. m = OS2IP(encoded_message)
    4. r = RandomInteger(0, n - 1)
    5. x = RSAVP1(pkS, r)
    6. z = m * x mod n
    7. r_inv = inverse_mod(r, n)
    8. blinded_msg = I2OSP(z, k)
    9. blind_inv = I2OSP(r_inv, k)
    10. return blinded_msg, blind_inv
    """
    k = byte_length(pkS.n)
    encoded_message = rsassa_pss_sign_encode(pkS.n, msg_hash)
    m = OS2IP(encoded_message)

    r = random_integer_uniform(1, pkS.n)
    r_inv = inverse_mod(r, pkS.n)
    assert (r * r_inv) % pkS.n == 1

    x = RSAVP1(pkS, r)
    z = (m * x) % pkS.n

    blinded_msg = I2OSP(z, k)
    blind_inv = I2OSP(r_inv, k)
    blind = I2OSP(r, k)  # This is output for test vector generation only
    return blinded_msg, blind_inv, blind


def rsassa_pss_blind_sign(skS, blinded_msg):
    """
    1. m = OS2IP(blinded_msg)
    2. s = RSASP1(skS, m)
    3. blind_sig = I2OSP(s, k)
    4. return blind_sig
    """
    k = byte_length(skS.n)

    m = OS2IP(blinded_msg)
    s = RSASP1(skS, m)
    blind_sig = I2OSP(s, k)
    return blind_sig


def rsassa_pss_sign_finalize(pkS, msg_hash, blind_sig, blind_inv):
    """
    1. z = OS2IP(blind_sig)
    2. r_inv = OS2IP(blind_inv)
    3. s = z * r_inv mod n
    4. result = rsassa_pss_sign_verify(pkS, msg, s)
    5. sig = I2OSP(s, k)
    6. If result = true, return s, else output "invalid signature" and stop
    """
    k = byte_length(pkS.n)

    z = OS2IP(blind_sig)
    r_inv = OS2IP(blind_inv)
    s = (z * r_inv) % pkS.n

    sig = I2OSP(s, k)
    if rsassa_pss_sign_verify(pkS, msg_hash, sig):
        return sig
    else:
        raise Exception("invalid signature")


def rsassa_pss_sign(skS, msg_hash):
    k = byte_length(skS.n)
    EM = rsassa_pss_sign_encode(pkS.n, msg_hash)
    m = OS2IP(EM)
    s = RSASP1(skS, m)
    sig = I2OSP(s, k)
    return sig


def rsassa_pss_sign_verify(pkS, msg_hash, sig):
    """
    1. If len(sig) != k, output false
    2. s = OS2IP(sig)
    3. m = RSAVP1(pkS, s)
    4. If RSAVP1 output "signature representative out of range", output false
    5. encoded_message = I2OSP(m, L_em)
    6. result = EMSA-PSS-VERIFY(msg, encoded_message, k_bits - 1).
    7. If result = "consistent", output true, otherwise output false
    8. output result
    """
    k_bits = bit_length(pkS.n)
    k = byte_length(pkS.n)

    if len(sig) != k:
        return False

    s = OS2IP(sig)
    m = RSAVP1(pkS, s)
    EM = I2OSP(m, k)

    mgf = lambda x, y: MGF1(x, int(y), msg_hash)
    return EMSA_PSS_VERIFY(msg_hash, EM, int(k_bits - 1), mgf, salt_length)


# https://github.com/pycrypto/pycrypto/blob/master/lib/Crypto/Signature/PKCS1_PSS.py
def MGF1(mgfSeed, maskLen, hash):
    """Mask Generation Function, described in B.2.1"""
    T = bytes([])
    for counter in range(ceil_div(maskLen, hash.digest_size)):
        c = long_to_bytes(counter, 4)
        T = T + hash.new(mgfSeed + c).digest()
    assert len(T) >= maskLen
    return T[:maskLen]


# https://github.com/pycrypto/pycrypto/blob/master/lib/Crypto/Signature/PKCS1_PSS.py
def EMSA_PSS_ENCODE(mhash, emBits, randFunc, mgf, sLen):
    """
    Implement the ``EMSA-PSS-ENCODE`` function, as defined
    in PKCS#1 v2.1 (RFC3447, 9.1.1).
    The original ``EMSA-PSS-ENCODE`` actually accepts the message ``M`` as input,
    and hash it internally. Here, we expect that the message has already
    been hashed instead.
    :Parameters:
     mhash : hash object
            The hash object that holds the digest of the message being signed.
     emBits : int
            Maximum length of the final encoding, in bits.
     randFunc : callable
            An RNG function that accepts as only parameter an int, and returns
            a string of random bytes, to be used as salt.
     mgf : callable
            A mask generation function that accepts two parameters: a string to
            use as seed, and the lenth of the mask to generate, in bytes.
     sLen : int
            Length of the salt, in bytes.
    :Return: An ``emLen`` byte long string that encodes the hash
            (with ``emLen = \ceil(emBits/8)``).
    :Raise ValueError:
        When digest or salt length are too big.
    """
    emLen = ceil_div(emBits, int(8))

    # Bitmask of digits that fill up
    lmask = 0
    for i in range(8 * emLen - emBits):
        lmask = lmask >> 1 | 0x80

    # Step 1 and 2 have been already done
    # Step 3
    if emLen < mhash.digest_size + sLen + 2:
        raise ValueError("Digest or salt length are too long for given key size.")
    # Step 4
    salt = bytes([])
    if randFunc and sLen > 0:
        salt = randFunc(sLen)
    # Step 5 and 6
    h = mhash.new(bchr(0x00) * 8 + mhash.digest() + salt)
    # Step 7 and 8
    db = bchr(0x00) * (emLen - sLen - mhash.digest_size - 2) + bchr(0x01) + salt
    # Step 9
    dbMask = mgf(h.digest(), emLen - mhash.digest_size - 1)
    # Step 10
    maskedDB = strxor(db, dbMask)
    # Step 11
    maskedDB = bchr(bord(maskedDB[0]) & int(~lmask)) + maskedDB[1:]
    # Step 12
    em = maskedDB + h.digest() + bchr(0xBC)
    return em


# https://github.com/pycrypto/pycrypto/blob/master/lib/Crypto/Signature/PKCS1_PSS.py
def EMSA_PSS_VERIFY(mhash, em, emBits, mgf, sLen):
    """
    Implement the ``EMSA-PSS-VERIFY`` function, as defined
    in PKCS#1 v2.1 (RFC3447, 9.1.2).

    ``EMSA-PSS-VERIFY`` actually accepts the message ``M`` as input,
    and hash it internally. Here, we expect that the message has already
    been hashed instead.

    :Parameters:
     mhash : hash object
            The hash object that holds the digest of the message to be verified.
     em : string
            The signature to verify, therefore proving that the sender really signed
            the message that was received.
     emBits : int
            Length of the final encoding (em), in bits.
     mgf : callable
            A mask generation function that accepts two parameters: a string to
            use as seed, and the lenth of the mask to generate, in bytes.
     sLen : int
            Length of the salt, in bytes.

    :Return: 0 if the encoding is consistent, 1 if it is inconsistent.

    :Raise ValueError:
        When digest or salt length are too big.
    """

    emLen = ceil_div(emBits, int(8))

    # Bitmask of digits that fill up
    lmask = 0
    for i in range(8 * emLen - emBits):
        lmask = lmask >> 1 | 0x80

    # Step 1 and 2 have been already done
    # Step 3
    if emLen < mhash.digest_size + sLen + 2:
        return False
    # Step 4
    if ord(em[-1:]) != 0xBC:
        return False
    # Step 5
    maskedDB = em[: emLen - mhash.digest_size - 1]
    h = em[emLen - mhash.digest_size - 1 : -1]
    # Step 6
    if lmask & bord(em[0]):
        return False
    # Step 7
    dbMask = mgf(h, emLen - mhash.digest_size - 1)
    # Step 8
    db = strxor(maskedDB, dbMask)
    # Step 9
    db = bchr(bord(db[0]) & int(~lmask)) + db[1:]
    # Step 10
    if not db.startswith(
        bchr(0x00) * (emLen - mhash.digest_size - sLen - 2) + bchr(0x01)
    ):
        return False
    # Step 11
    salt = bytes([])
    if sLen:
        salt = db[-sLen:]
    # Step 12 and 13
    hp = mhash.new(bchr(0x00) * 8 + mhash.digest() + salt).digest()
    # Step 14
    if h != hp:
        return False
    return True


def rsa_key_gen(p_bits):
    p = number.getPrime(p_bits)
    q = number.getPrime(p_bits)
    phi = (p - 1) * (q - 1)

    e = 65537
    d = inverse_mod(e, phi)
    n = p * q

    skS = PrivateKey(n, p, q, d)
    pkS = PublicKey(n, e)

    return skS, pkS


def run_signature_scheme(skS, pkS, msg):
    msg_hash = SHA384.new()
    msg_hash.update(msg)

    # Run the non-blind variant
    sig = rsassa_pss_sign(skS, msg_hash)
    valid = rsassa_pss_sign_verify(pkS, msg_hash, sig)
    assert valid

    k = byte_length(pkS.n)
    encoded_message = rsassa_pss_sign_encode(pkS.n, msg_hash)

    # Run the blind variant
    blinded_msg, blind_inv, blind = rsassa_pss_sign_blind(pkS, msg_hash)
    blind_sig = rsassa_pss_blind_sign(skS, blinded_msg)
    sig = rsassa_pss_sign_finalize(pkS, msg_hash, blind_sig, blind_inv)
    valid = rsassa_pss_sign_verify(pkS, msg_hash, sig)
    assert valid

    vector = {"name": "Blind RSA-PSS(%d)" % (bit_length(pkS.n))}
    vector["p"] = to_hex(I2OSP(skS.p, byte_length(skS.p)))
    vector["q"] = to_hex(I2OSP(skS.q, byte_length(skS.q)))
    vector["n"] = to_hex(I2OSP(pkS.n, byte_length(pkS.n)))
    vector["e"] = to_hex(I2OSP(pkS.e, byte_length(pkS.e)))
    vector["d"] = to_hex(I2OSP(skS.d, byte_length(skS.d)))
    vector["msg"] = to_hex(msg)
    vector["encoded_message"] = to_hex(encoded_message)
    vector["blinded_msg"] = to_hex(blinded_msg)
    vector["inv"] = to_hex(blind_inv)
    vector["r"] = to_hex(blind)
    vector["blind_sig"] = to_hex(blind_sig)
    vector["sig"] = to_hex(sig)
    vector["salt_length"] = salt_length
    vector["mgf"] = "MGF1"
    vector["hash"] = "SHA384"

    return [vector]  # TODO(caw): vary more parameters


def run_partially_blind_signature_scheme(skS, pkS, msg, tweak, C, H):
    vectors = []
    for c in C:
        # First, augment the message input
        msg_hash = SHA384.new()
        msg_hash.update(c)
        msg_hash.update(msg)

        # Next, augment the public and private keys
        public_tweak = augment(c, H, tweak)
        print("Tweak size", number.size(public_tweak), number.size(pkS.n))
        phi = (skS.p - 1) * (skS.q - 1)
        private_tweak = inverse_mod(public_tweak, phi)

        # TODO(caw): pkS.e should be set to public_tweak, and skS.d should be set to private_tweak, but
        # servers will derive it on the fly
        skS = PrivateKey(skS.n, skS.p, skS.q, private_tweak)
        pkS = PublicKey(pkS.n, public_tweak)

        k = byte_length(pkS.n)
        encoded_message = rsassa_pss_sign_encode(pkS.n, msg_hash)

        # Run the blind variant
        blinded_msg, blind_inv, blind = rsassa_pss_sign_blind(pkS, msg_hash)
        blind_sig = rsassa_pss_blind_sign(skS, blinded_msg)
        sig = rsassa_pss_sign_finalize(pkS, msg_hash, blind_sig, blind_inv)
        valid = rsassa_pss_sign_verify(pkS, msg_hash, sig)
        assert valid

        vector = {
            "name": "Partially Blind RSA-PSS(%d, %d)" % (bit_length(pkS.n), len(C))
        }
        vector["p"] = to_hex(I2OSP(skS.p, byte_length(skS.p)))
        vector["q"] = to_hex(I2OSP(skS.q, byte_length(skS.q)))
        vector["tweak"] = to_hex(tweak)
        vector["c"] = to_hex(c)
        vector["public_tweak"] = to_hex(I2OSP(public_tweak, byte_length(public_tweak)))
        vector["private_tweak"] = to_hex(
            I2OSP(private_tweak, byte_length(private_tweak))
        )
        vector["n"] = to_hex(I2OSP(pkS.n, byte_length(pkS.n)))
        vector["msg"] = to_hex(msg)
        vector["encoded_msg"] = to_hex(encoded_message)
        vector["blinded_msg"] = to_hex(blinded_msg)
        vector["blind_inv"] = to_hex(blind_inv)
        vector["blind"] = to_hex(blind)
        vector["blind_sig"] = to_hex(blind_sig)
        vector["sig"] = to_hex(sig)
        vector["salt_length"] = salt_length
        vector["mgf"] = "MGF1"
        vector["hash"] = "SHA384"

        vectors.append(vector)
    return vectors


def to_hex(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    assert isinstance(octet_string, bytes)
    return "0x" + "".join("{:02x}".format(c) for c in octet_string)


def wrap_print(arg, *args):
    line_length = 68
    string = arg + " " + " ".join(args)
    for hunk in (
        string[0 + i : line_length + i] for i in range(0, len(string), line_length)
    ):
        if hunk and len(hunk.strip()) > 0:
            print(hunk)


def print_blob(name, blob):
    wrap_print(name + " = " + to_hex(blob))


def print_value(name, value):
    wrap_print(name + " = " + value)


PRIME_LENGTH = int(2048)
skS, pkS = rsa_key_gen(PRIME_LENGTH)
k_bits = int(number.size(pkS.n))
k = number.ceil_div(k_bits, int(8))

# Sanity check RSA operations
phi = (skS.p - 1) * (skS.q - 1)
m = random.randint(3, phi)
s = RSASP1(skS, m)
mm = RSAVP1(pkS, s)
assert m == mm


def print_vectors(vectors):
    for vector in vectors:
        print("## " + vector["name"])
        print("")
        keys = [
            "p",
            "q",
            "n",
            "e",
            "d",
            "msg",
            "c",
            "tweak",
            "public_tweak",
            "private_tweak",
            "blind",
            "blind_inv",
            "blinded_msg",
            "blind_sig",
            "sig",
            "salt_length",
            "mgf",
            "hash",
        ]
        for k in keys:
            if k in vector:
                print_value(k, vector[k])
        print("")


# Public key augmentation and auxiliary data set parameters
AUGMENTER_LENGTH = 32
MAX_ATTEMPTS = 10000
C_lengths = [2]  # [2 ** 0, 2 ** 1, 2 ** 5, 2 ** 10, 2 ** 20]

# Augmentation hash function
H_8 = lambda x: hasher(x, 8)
H_16 = lambda x: hasher(x, 16)
H_32 = lambda x: hasher(x, 32)

"""
p = 883416117755151419680574820861997605267773650743990218246746162560254620925624164412638707356499610317260572683168086156913722892505791857530255884084009818777437690578096264494839506594114577257503900119680322774281678272534473704004249032441693873942992893247038627336598010806316030913711591424520509287956642237058540892123681002420088538990506463647513458927432906712787311817228295421165970548527232795418309899398093372854650840124350015072722840245204706653478207548187134113151810966930856903362694470467733689155648581059507588652338177794414710845547381808248943314392301139126397093452323609776140243031354848039663782365039464980939901215822973210006910860152301274666553339790949243986307104627914561785293320973566346050312838565902010945447508020707695989765601466048690896700282251437221857909653380832869023159906272472622983206823430913992112423960043148273660748195752853470079485340793889950604661090746105862747474919923155588320926089677291999986366204486732492659030482519654800825952211601484605177579926861202818772420384878450751561224402444485475729079164965854604270110950409947584975145871242048218451202179099163261912351573243781318540038887240154773420134138015771822145383337148898692589420184362287
q = 940553052294961067477905617321673854151215289671564384952422031391097024308778649887256105752569385084207380092530684276466476031521600564614512384148458999973551019426856745167903806403132490458297347874667281799151379675265559376830545414666482007884454712029369555667181926135228716204630275148194972869405709899323805721261627220278278387618602134559167755662172747682567988020284422671359915565839059245360743821812667622529390638137082888808297159640801270945409347157370769032038101468475509703093204650238239387731492511811519703534080471943646365787477521222142021434904136385746501153306363933511117950496016604412258076820849052767012865252942121122604341657612303983446527764173481454999975009730864307806813589853519827912015311069036438541572348928987889711067820002196976228007430504487666932787494382707415828805068480798950108618135863053982917883537107429520987543168546700168942639473120407868801032490211876436997143537028200017692498685117407767054044306956152115463829541671156264015785702480810807466987713349053472072393190746281729330211752148468865249661993706863604487098229405376444162012340762217663068285273329386713433050440677536440082086645125112641941344402203166812161362273815234203282658167959903
d = 764832995236130814226473420048018993386192405803027631224444464450680228955519695120118979299383232932355019596614854857669297526610782408272384462181659835172981874585385161202576901448361610113888137885826824251085077138262153602082937838577546270216605869016345590737049303676498557584156090456636018351302921996729142321435121307495651901455406394666127863992331152129524043668788711962380681632107562704973889768661833909628959972892434938116969994141360874626171928117853899487795137431797130581213220175638573980235164804303984377803331709245076876805575238966607143372681913527796437588505695958355779850582287770922441518669703032177168987833350250603887952902257192889507183260689567619045434528351319356428095913014919091383112791808609592987225987297732624011647969981992354496887219590741685236743252037024525875160296175356061063332788877850792355665484283665222389912270375845635565235541243313943570115771585398609027499656160451590716899684932112029329077894422770237659456917643967864736350500737814663806293898561044281320392209124898300653898862140270365060334416926720236937659355443144559364445254199861994496282408183256330268741943213912448766742430686633895127889856975688415640635086885432388287785899918376568557137263295713603176688402427068152330780290455911499083805480041368661377872916989880706408270608312194905964911559875204510914732731283591693664855809600460580415004150389480059245438124370577682010018890911024337153363282653594356368006684418807573484729557557089224514108324878122601987671976563042639071671169299021149557833059599183211396766316121898282880948757660615034841248441790761567200894521691042436023258054464007476284347372785085846902857952787013447739992509905206973289982832979822649490994096248216421518333203887658748584217605354718595824022173083269086448157300143038002201800273472143226133614525077581520437640474794205792815875709367101254160166424305835154107888816600853215501482448866559574852431640313567195722534938137457282057297471422839571842154065422555190462727273147930636391078350375862963923660427204611064218245520770650828049560584845244980114873984607784827977800297686595146054301499364966515651349163035582156096150630490934232695364588709852628932286326187239077438723925372204608229893197172319879798721114791732995263979780197430556974883407131286931044962396077448445338093398869911138420686547913419574220154255744868556141609250198604848529640825349809213975863023183546480394157
e = 590356323698409288717944542186222495541992234181977649640161290370290784264791383624976330830978579006704156654461537496374990872848769552623493647882236796417207889044115564463465094379317589884480259744121071709091137953766176297712304626377683204406903841815669915775174647574081357000403872549184131183372950516101795116169861132605356452433934763289468701499651999379341201697786972461775382070436744136103961335588496606512432383869081156179387597256151163897200077810626398817766726819077735777000160848219401064454499939013441734078403165930343923051025726161099644493675824755910169219681599353184062634223437194608946019167959638862534472286076332963289291829041798724404237150122053698286289962861139196556959841831729505588852646508335205777225230225078958271973685265753504371828261286079003117335991107888402911527492219682359013739965492801423189780071524222346791230036695570194351086775348521508068045175614608373672547018255207378472369966281675472261544478602778339469810850589871123649394738654825973501440985019844939653710554534154869349664314559389113428065744046422240188749770799558261774430637978153889470334458294481828857234057431859821483784052625595243255109167188529580417971367125004124524395406352176736864763062927826994182341117405947958874574387615225834064130220104219286843864863479297828731878345921596283616671825902334144922975072342252965538248651373001451617588634896446181710364695489942419311779702901994614842056544149372882663341125818947205893825816838460371786640916937132847346361693365410756131515601166875587702482798763202253438947361968829942590087594241127134456219772874615443208952656410624850211652504394771476920734317679475770112653391644898440443534613751161002888044364732758823945594566210719859872527572708490985163048089193519667013900820137585048876854154994456716230108898268378202722176802730587636591651085139680944880675311447921980573313159658127844251565956218949212912455903207669095769434609318221659633599765680082616117004944274777849173794382019524852305696917084075449486408334708662846083448809896928800660127711863574085181889880625254952989201444666600584024046735066442022904474895313181152117546035424795268309641224202620897971355855671200556031270811521336502709712311385030461056496305766520878831352648770072945240813605424065756165846012807516511559929131039170104069977231170182668579203441661882842120892475502484316235686133826708617055826910324640500514316398387419738765921
s = 8afbef9c14e3ac25a0f26583e36cc34edb73580615b11dbf2aa708117e8704bb
"""

msg = "hello world".encode("utf-8")

test_vectors = []
test_vectors.extend(run_signature_scheme(skS, pkS, msg))

# for C_len in C_lengths:
#     C = [str(i).encode("utf-8") for i in range(C_len)]
#     try:
#         s = find_augmenter(C, H_32, phi)
#         test_vectors.extend(run_partially_blind_signature_scheme(skS, pkS, msg, s, C, H_32))
#     except:
#         pass

# print_vectors(test_vectors)
print(json.dumps(test_vectors, indent=4))
