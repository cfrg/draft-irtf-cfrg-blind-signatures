#! /usr/bin/env python3

import json
import random
from Crypto.Util.number import size, inverse, ceil_div, GCD
from Crypto.Hash import SHA384
from Crypto.Util.strxor import strxor
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature import pss
from Crypto.Signature.pss import MGF1

# Fixes the PRNG for reproducible test vector generation.
random.seed(a="draft-irtf-cfrg-blind-signatures", version=2)

H = SHA384
MgfHash = SHA384

def wrap_print(name, value, file):
    line_length = 68
    string = name + " = " + value
    for hunk in (
        string[0 + i : line_length + i] for i in range(0, len(string), line_length)
    ):
        if hunk:
            stripped_hunk = hunk.strip()
            if len(stripped_hunk) > 0:
                print(stripped_hunk, file=file)


def OS2IP(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def I2OSP(i: int, length: int) -> bytes:
    return i.to_bytes(length=length, byteorder="big")


def to_hex(n):
    h = hex(n)[2:]
    if len(h) % 2 != 0:
        h = "0" + h
    return h

def EMSA_PSS_ENCODE(kBits: int, msg: bytes, sLen: int, salt: bytes = None) -> bytes:
    m_hash = H.new(msg).digest()
    hLen = H.digest_size

    emBits = kBits - 1
    emLen = ceil_div(emBits, 8)
    assert emLen >= hLen + sLen + 2

    lmask = 0
    for _ in range(0, 8 * emLen - emBits):
        lmask = lmask >> 1 | 0x80

    if salt is None:  # for test vector verification
        salt = random.randbytes(sLen)

    m_prime = bytes(8) + m_hash + salt
    h = MgfHash.new(m_prime).digest()
    ps = bytes(emLen - sLen - hLen - 2)
    db = ps + bytes([0x01]) + salt
    dbMask = MGF1(h, emLen - hLen - 1, MgfHash)
    masked_db = strxor(db, dbMask)
    masked_db = bytes([masked_db[0] & (~lmask)]) + masked_db[1:]
    encoded_msg = masked_db + h + bytes([0xBC])

    return encoded_msg


def RSAVP1(public_key: RsaKey, r: int) -> int:
    e = public_key.e
    n = public_key.n
    return pow(r, e, n)


def random_integer_uniform(min: int, max: int) -> int:
    # Implement rejection sampling to return an integer in [min, max).
    # This is for reference only; most cryptographic libraries include
    # functions to generate random integers from a uniform distribution.
    range = max - min
    rangeBits = size(range - 1)
    rangeLen = ceil_div(rangeBits, 8)
    mask = (1 << rangeBits) - 1
    while True:
        randomBytes = random.randbytes(rangeLen)
        r = OS2IP(randomBytes) & mask
        if r < range:
            return min + r


def is_coprime(a, b):
    return GCD(a, b) == 1


def rsabssa_randomize(msg: bytes) -> bytes:
    msg_prefix = random.randbytes(32)

    return msg_prefix + msg


def rsabssa_blind(
    public_key: RsaKey, msg: bytes, sLen: int, r: int = None, salt: bytes = None
) -> tuple[bytes, int]:
    n = public_key.n
    kBits = n.bit_length()
    kLen = ceil_div(kBits, 8)
    encoded_msg = EMSA_PSS_ENCODE(kBits, msg, sLen, salt)
    m = OS2IP(encoded_msg)

    if not is_coprime(m, n):
        raise "Invalid input"

    if r is None:  # for test vector verification
        r = random_integer_uniform(1, n)

    try:
        inv = inverse(r, n)
    except ValueError:
        raise "Invalid blind"

    x = RSAVP1(public_key, r)
    z = (m * x) % n
    blinded_msg = I2OSP(z, length=kLen)

    return blinded_msg, inv


def rsabssa_blind_sign(secret_key: RsaKey, blinded_msg: bytes) -> bytes:
    kLen = secret_key.size_in_bytes()
    if len(blinded_msg) != kLen:
        raise "Unexpected input size"
    n = secret_key.n
    d = secret_key.d
    m = OS2IP(blinded_msg)
    if m >= n:
        raise "Invalid message length"
    s = pow(m, d, n)
    blind_sig = I2OSP(s, length=kLen)
    return blind_sig


def rsabssa_finalize(
    public_key: RsaKey, blind_sig: bytes, inv: int, msg: bytes, sLen: int
) -> bytes:
    kLen = public_key.size_in_bytes()
    n = public_key.n
    z = OS2IP(blind_sig)
    s = (z * inv) % n
    sig = I2OSP(s, length=kLen)
    rsa_pss_verify(public_key, sig, msg, sLen)
    return sig


def rsa_pss_verify(public_key: RsaKey, sig: bytes, msg: bytes, sLen: int) -> None:
    mgf = lambda x, y: MGF1(x, y, MgfHash)
    verifier = pss.new(public_key, salt_bytes=sLen, mask_func=mgf)
    verifier.verify(H.new(msg), sig)  # standard RSASSA-PSS/MGF1 verification function

class Vector:
    def __init__(self, name, with_salt, is_randomized) -> None:
        self.name = name
        self.p = 0xE1F4D7A34802E27C7392A3CEA32A262A34DC3691BD87F3F310DC75673488930559C120FD0410194FB8A0DA55BD0B81227E843FDCA6692AE80E5A5D414116D4803FCA7D8C30EAAAE57E44A1816EBB5C5B0606C536246C7F11985D731684150B63C9A3AD9E41B04C0B5B27CB188A692C84696B742A80D3CD00AB891F2457443DADFEBA6D6DAF108602BE26D7071803C67105A5426838E6889D77E8474B29244CEFAF418E381B312048B457D73419213063C60EE7B0D81820165864FEF93523C9635C22210956E53A8D96322493FFC58D845368E2416E078E5BCB5D2FD68AE6ACFA54F9627C42E84A9D3F2774017E32EBCA06308A12ECC290C7CD1156DCCCFB2311
        self.q = 0xC601A9CAEA66DC3835827B539DB9DF6F6F5AE77244692780CD334A006AB353C806426B60718C05245650821D39445D3AB591ED10A7339F15D83FE13F6A3DFB20B9452C6A9B42EAA62A68C970DF3CADB2139F804AD8223D56108DFDE30BA7D367E9B0A7A80C4FDBA2FD9DDE6661FC73FC2947569D2029F2870FC02D8325ACF28C9AFA19ECF962DAA7916E21AFAD09EB62FE9F1CF91B77DC879B7974B490D3EBD2E95426057F35D0A3C9F45F79AC727AB81A519A8B9285932D9B2E5CCD347E59F3F32AD9CA359115E7DA008AB7406707BD0E8E185A5ED8758B5BA266E8828F8D863AE133846304A2936AD7BC7C9803879D2FC4A28E69291D73DBD799F8BC238385
        self.n = 0xAEC4D69ADDC70B990EA66A5E70603B6FEE27AAFEBD08F2D94CBE1250C556E047A928D635C3F45EE9B66D1BC628A03BAC9B7C3F416FE20DABEA8F3D7B4BBF7F963BE335D2328D67E6C13EE4A8F955E05A3283720D3E1F139C38E43E0338AD058A9495C53377FC35BE64D208F89B4AA721BF7F7D3FEF837BE2A80E0F8ADF0BCD1EEC5BB040443A2B2792FDCA522A7472AED74F31A1EBE1EEBC1F408660A0543DFE2A850F106A617EC6685573702EAAA21A5640A5DCAF9B74E397FA3AF18A2F1B7C03BA91A6336158DE420D63188EE143866EE415735D155B7C2D854D795B7BC236CFFD71542DF34234221A0413E142D8C61355CC44D45BDA94204974557AC2704CD8B593F035A5724B1ADF442E78C542CD4414FCE6F1298182FB6D8E53CEF1ADFD2E90E1E4DEEC52999BDC6C29144E8D52A125232C8C6D75C706EA3CC06841C7BDA33568C63A6C03817F722B50FCF898237D788A4400869E44D90A3020923DC646388ABCC914315215FCD1BAE11B1C751FD52443AAC8F601087D8D42737C18A3FA11ECD4131ECAE017AE0A14ACFC4EF85B83C19FED33CFD1CD629DA2C4C09E222B398E18D822F77BB378DEA3CB360B605E5AA58B20EDC29D000A66BD177C682A17E7EB12A63EF7C2E4183E0D898F3D6BF567BA8AE84F84F1D23BF8B8E261C3729E2FA6D07B832E07CDDD1D14F55325C6F924267957121902DC19B3B32948BDEAD5
        self.e = 0x010001
        self.d = 0x0D43242AEFE1FB2C13FBC66E20B678C4336D20B1808C558B6E62AD16A287077180B177E1F01B12F9C6CD6C52630257CCEF26A45135A990928773F3BD2FC01A313F1DAC97A51CEC71CB1FD7EFC7ADFFDEB05F1FB04812C924ED7F4A8269925DAD88BD7DCFBC4EF01020EBFC60CB3E04C54F981FDBD273E69A8A58B8CEB7C2D83FBCBD6F784D052201B88A9848186F2A45C0D2826870733E6FD9AA46983E0A6E82E35CA20A439C5EE7B502A9062E1066493BDADF8B49EB30D9558ED85ABC7AFB29B3C9BC644199654A4676681AF4BABCEA4E6F71FE4565C9C1B85D9985B84EC1ABF1A820A9BBEBEE0DF1398AAE2C85AB580A9F13E7743AFD3108EB32100B870648FA6BC17E8ABAC4D3C99246B1F0EA9F7F93A5DD5458C56D9F3F81FF2216B3C3680A13591673C43194D8E6FC93FC1E37CE2986BD628AC48088BC723D8FBE293861CA7A9F4A73E9FA63B1B6D0074F5DEA2A624C5249FF3AD811B6255B299D6BC5451BA7477F19C5A0DB690C3E6476398B1483D10314AFD38BBAF6E2FBDBCD62C3CA9797A420CA6034EC0A83360A3EE2ADF4B9D4BA29731D131B099A38D6A23CC463DB754603211260E99D19AFFC902C915D7854554AABF608E3AC52C19B8AA26AE042249B17B2D29669B5C859103EE53EF9BDC73BA3C6B537D5C34B6D8F034671D7F3A8A6966CC4543DF223565343154140FD7391C7E7BE03E241F4ECFEB877A051
        self.msg = I2OSP(
            0x8F3DC6FB8C4A02F4D6352EDF0907822C1210A9B32F9BDDA4C45A698C80023AA6B59F8CFEC5FDBB36331372EBEFEDAE7D,
            length=48,
        )
        self.msg_prefix = None
        self.input_msg = None
        sLen = 48
        salt = I2OSP(
            0x051722B35F458781397C3A671A7D3BD3096503940E4C4F1AAA269D60300CE449555CD7340100DF9D46944C5356825ABF,
            length=sLen,
        )
        self.salt = with_salt * salt
        self.sLen = with_salt * sLen

        self.r = 0x80682C48982407B489D53D1261B19EC8627D02B8CDA5336750B8CEE332AE260DE57B02D72609C1E0E9F28E2040FC65B6F02D56DBD6AA9AF8FDE656F70495DFB723BA01173D4707A12FDDAC628CA29F3E32340BD8F7DDB557CF819F6B01E445AD96F874BA235584EE71F6581F62D4F43BF03F910F6510DEB85E8EF06C7F09D9794A008BE7FF2529F0EBB69DECEF646387DC767B74939265FEC0223AA6D84D2A8A1CC912D5CA25B4E144AB8F6BA054B54910176D5737A2CFF011DA431BD5F2A0D2D66B9E70B39F4B050E45C0D9C16F02DEDA9DDF2D00F3E4B01037D7029CD49C2D46A8E1FC2C0C17520AF1F4B5E25BA396AFC4CD60C494A4C426448B35B49635B337CFB08E7C22A39B256DD032C00ADDDAFB51A627F99A0E1704170AC1F1912E49D9DB10EC04C19C58F420212973E0CB329524223A6AA56C7937C5DFFDB5D966B6CD4CBC26F3201DD25C80960A1A111B32947BB78973D269FAC7F5186530930ED19F68507540EED9E1BAB8B00F00D8CA09B3F099AAE46180E04E3584BD7CA054DF18A1504B89D1D1675D0966C4AE1407BE325CDF623CF13FF13E4A28B594D59E3EADBADF6136EEE7A59D6A444C9EB4E2198E8A974F27A39EB63AF2C9AF3870488B8ADAAD444674F512133AD80B9220E09158521614F1FAADFE8505EF57B7DF6813048603F0DD04F4280177A11380FBFC861DBCBD7418D62155248DAD5FDEC0991F
        self.inv = None

        self.secret_key = RSA.construct((self.n, self.e, self.d, self.p, self.q), consistency_check=True)
        self.public_key = self.secret_key.public_key()
        self.is_randomized = is_randomized

        self.blinded_msg = None
        self.blind_sig = None
        self.sig = None

def encode_txt(obj, file):
    print("\n## {} Test Vector".format(obj.name), file=file)
    print("~~~", file=file)
    for key, value in obj.__dict__.items():
        if key in ["name", "is_randomized", "secret_key", "public_key"]:
            continue
        if isinstance(value, int):
            value = "0x" + to_hex(value)
        elif isinstance(value, bytes):
            value = value.hex()
        wrap_print(key, value, file)
    print("~~~", file=file)

def encode_JSON(vec):
    out = {}
    for key, value in vec.__dict__.items():
        if isinstance(value,int):
            value = "0x" + to_hex(value)
        elif isinstance(value,bytes):
            value = value.hex()
        elif isinstance(value,RsaKey):
            continue
        out[key] = value
    return out

def run_protocol(v) -> None:
    if v.is_randomized:
        v.input_msg = rsabssa_randomize(v.msg)
        v.msg_prefix = v.input_msg[0:32]
    else:
        v.input_msg = v.msg
        v.msg_prefix = bytes()

    while True:
        try:
            v.blinded_msg, v.inv = rsabssa_blind(v.public_key, v.input_msg, v.sLen, v.r, v.salt)
        finally:
            break
    v.blind_sig = rsabssa_blind_sign(v.secret_key, v.blinded_msg)
    v.sig = rsabssa_finalize(v.public_key, v.blind_sig, v.inv, v.input_msg, v.sLen)

def test_variants() -> None:
    vectors = [
        Vector("RSABSSA-SHA384-PSS-Randomized",        with_salt=True,  is_randomized=True),
        Vector("RSABSSA-SHA384-PSSZERO-Randomized",    with_salt=False, is_randomized=True),
        Vector("RSABSSA-SHA384-PSS-Deterministic",     with_salt=True,  is_randomized=False),
        Vector("RSABSSA-SHA384-PSSZERO-Deterministic", with_salt=False, is_randomized=False),
    ]

    for vec in vectors:
        run_protocol(vec)

    with open("test_vector.txt", "w") as file:
        for vec in vectors:
            encode_txt(vec, file)

    with open("test_vector.json", "w") as file:
        json.dump([ encode_JSON(vec) for vec in vectors ], file, indent=2)

test_variants()
