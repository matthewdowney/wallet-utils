import hashlib
from functools import reduce
from hashlib import sha256

from wallet_utils.btc_script import *

try:
    from bip32utils import BIP32Key, Base58
except ImportError:
    BIP32Key = Base58 = None
    raise ImportError("Please install the bip32utils project: $ pip install git+https://github.com/prusnak/bip32utils")

try:
    # noinspection PyPackageRequirements
    import sha3


    def keccak_256():
        return sha3.keccak_256()
except Exception:
    raise ImportError("Need the pysha3 to use Ethereum's special keccak variation (which doesn't conform to the "
                      "eventual sha3 standard): $ pip install pysha3")

# BIP32 Keys are specified as hardened (derived using the private key) if their index is >= 2**31. These utils are for
# xpubs only--no private keys--so all indexes must be < MAX_IDX
MAX_IDX = 0x80000000

# Bytes that prefix address hashes for different types.
# _test suffixed keys represent test net address prefixes.
ADDR_PREFIX_BYTES = {
    'p2pkh': b"\x00",
    'p2pkh_test': b"\x6f",
    'p2sh': b"\x05",
    'p2sh_test': b"\xc4"
}

# xpub serialization format: The indexes for each xpub field in a byte array.
XPUB_FORMAT = {
    'version':      (0,  4),
    'depth':        (4,  5),
    'fingerprint':  (5,  9),
    'child_number': (9,  13),
    'chain_code':   (13, 45),
    'key':          (45, 78)
}


def _prefix_bytes(addr_type, testnet=False):
    return ADDR_PREFIX_BYTES[addr_type + ('_test' if testnet else '')]


def xpub_bytes_to_field_bytes(xpub_bytes, field_name):
    """
    From an XPUB that's been Base58 decoded into bytes, get the bytes for a particular field.
    :param xpub_bytes: Byte encoded xpub.
    :param field_name: One of version, depth, fingerprint, child_number, chain_code, key.
    :return: The bytes for the requested field.
    """
    start, end = XPUB_FORMAT[field_name]
    return xpub_bytes[start:end]


def xpub_to_child_xpub(xpub, idx):
    """
    Get the child xpub for a given xpub and index. E.g. if `xp` is the xpub for m/44'/0'/0', then
    `xpub_to_child_xpub(xp, i)` will give the xpub corresponding to m/44'/0'/0'/i.
    :param xpub: Base58 encoded xpub.
    :param idx: Integer, non-hardened index (idx < 2**31).
    :return: Base58 encoded xpub.
    """
    assert 0 <= idx < MAX_IDX, \
        "Indexes must be >= 0 and < 2^31 (indexes >= 2^31 must be derived as hardened, which is not possible with an " \
        "xpub). "
    # TODO: This can return None if the left 32 bytes >= curve order or if point = Infinity (chances 1/2^127, but should be handled)
    # TODO: Replace object creation with faster implemenation
    # TODO: Try to simplify `ys = (x**3+7) % FIELD_ORDER` to pow(x, 3, FIELD_ORDER) + (7 % FIELD_ORDER) & check performance
    return BIP32Key.fromExtendedKey(xpub).CKDpub(idx).ExtendedKey(private=False)


def xpub_at_path(root_node, *path):
    """
    Follow a (non-hardened) hierarchy from a root node. E.g. if `rn` is the xpub for account #1 (m/44'/0'/1'), the first
    receiving address (m/44'/0'/1'/0/1) and change address (m/44'/0'/1'/1/1) are `xpub_at_path(rn, 0, 1)` and
    `xpub_at_path(rn, 1, 1)`, respectively.
    :param root_node: Base58 encoded xpub.
    :param path: The path to append to the current node as an integer list, e.g. to append the path /0/1/2 use 0, 1, 2.
    :return: Base58 encoded xpub.
    """
    return reduce(xpub_to_child_xpub, path, root_node)


def xpub_to_pk(xpub):
    """
    Derive a compressed public key from an xpub.
    :param xpub: Base58 encoded xpub.
    :return: Hex string compressed public key.
    """
    # Last 33 bytes of xpub are the compressed public key
    return xpub_bytes_to_field_bytes(Base58.check_decode(xpub), 'key').hex()


# TODO: Get rid of this method, and just add an uncompress_pk method
def xpub_to_uncompressed_pk(xpub):
    """
    Derive an uncompressed public key from an xpub. Let the excellent bip32utils library create the point from the xpub.
    :param xpub: Base58 encoded xpub.
    :return: Hex string uncompressed public key.
    """
    ec_point = BIP32Key.fromExtendedKey(xpub).K.pubkey.point

    def hx(i):
        without_prefix = hex(i)[2:]
        padding = 64 - len(without_prefix)  # values should be 32 bytes (64 hex chars)
        return (padding * "0") + without_prefix

    return '04' + hx(ec_point.x()) + hx(ec_point.y())


def pk_to_p2pkh_addr(pk, testnet=False):
    """
    Compressed public key (hex string) -> p2pkh address. 'Legacy Bitcoin address.'
    """
    pk_bytes = bytes.fromhex(pk)
    assert is_compressed_pk(pk_bytes), "Only use compressed public keys please."
    return Base58.check_encode(_prefix_bytes('p2pkh', testnet=testnet) + hash160_bytes(pk_bytes))


def pk_to_ethereum_addr(uncompressed_pk):
    """
    Uncompressed public key (hex string) -> Ethereum address.
    """
    pk_bytes = bytes.fromhex(uncompressed_pk)
    assert is_uncompressed_pk(pk_bytes), \
        'Only uncompressed public keys can be used to generate ethereum addresses. (And I don\'t want to implement ' \
        'the decompression.) '
    pk_bytes = pk_bytes[1:]  # Strip the initial 0x04 byte
    kc = keccak_256()
    kc.update(pk_bytes)
    return "0x" + kc.digest()[-20:].hex()


def pk_to_p2wpkh_in_p2sh_addr(pk, testnet=False):
    """
    Compressed public key (hex string) -> p2wpkh nested in p2sh address. 'SegWit address.'
    """
    pk_bytes = bytes.fromhex(pk)
    assert is_compressed_pk(pk_bytes), \
        "Only compressed public keys are compatible with p2sh-p2wpkh addresses. See BIP49."

    # Script sig is just 0 + PUSH(20){hash160(cpk)}
    script_sig = OP_0 + push_bytes(hash160_bytes(pk_bytes))

    # Address is then prefix + hash160(script_sig)
    address = Base58.check_encode(_prefix_bytes('p2sh', testnet=testnet) + hash160_bytes(script_sig))
    return address


def pks_to_p2sh_multisig_addr(m, *pks, testnet=False):
    """
    :param m: The 'm' in m-of-n; the number of required signatures.
    :param pks: The public keys involved in the multisig. `len(pks) == n` in m-of-n.
    :return: A base 58 encoded address. (The p2sh address prefix + the hash of the redeem script.)
    """
    redeem_script = _p2sh_multisig_script(m, *pks)
    assert len(redeem_script) <= 500, "Spending script is at most 500 bytes (it is valid /and/ standard)"
    return Base58.check_encode(_prefix_bytes("p2sh", testnet=testnet) + hash160_bytes(redeem_script))


def _p2sh_multisig_script(m, *pks):
    assert len(pks) <= 20, "keys passed to OP_CHECKMULTISIG <= 20"
    # Sort the pks and put together the opcodes to push each pk to the stack
    pks = sorted(pks)
    push_pks = reduce(lambda a, b: a + push_bytes(b), map(bytes.fromhex, pks), b'')
    n = op_n(len(pks))  # The 'n' part of m-of-n

    # Format is <OP_{M required}> <A pubkey> ... <N pubkey> <OP_{N keys}> <OP_CHECKMULTISIG>
    return op_n(m) + push_pks + n + OP_CHECKMULTISIG


def compress_pk(uncompressed_pk):
    """
    Uncompressed public key (hex string) -> compressed public key (hex string). Public key is (04, x, y) where 04 is a
    flag & x, y are the x, y elliptic curve coordinates. Compressed key is (02 + y's parity, x).
    """
    pk_bytes = bytes.fromhex(uncompressed_pk)
    assert is_uncompressed_pk(pk_bytes), "Provided key is uncompressed."
    pk_bytes = pk_bytes[1:]  # Remove the x04 prefix
    x, y = pk_bytes[:32], pk_bytes[32:]  # Split out the x, y ec points
    parity_flag = (b'\x03' if y[-1] & 1 else b'\x02')
    return (parity_flag + x).hex()


def hash160_bytes(byte_input):
    """
    Type is bytes -> bytes.
    """
    return hashlib.new('ripemd160', sha256(byte_input).digest()).digest()


def is_compressed_pk(pk_bytes):
    """
    Compressed public keys are 32 bytes of the pk prefixed with a parity byte.
    :return True for valid compressed format.
    """
    return len(pk_bytes) == 33 and (pk_bytes.startswith(b"\x02") or pk_bytes.startswith(b"\x03"))


def is_uncompressed_pk(pk_bytes):
    """
    Uncompressed public keys are 65 bytes long and prefixed by '04'.
    :return True for valid uncompressed format.
    """
    return len(pk_bytes) == 65 and pk_bytes.startswith(b"\x04")
