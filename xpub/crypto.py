import hashlib
from functools import reduce
from hashlib import sha256
from xpub.btc_script import *

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


def _prefix_bytes(addr_type, testnet=False):
    return ADDR_PREFIX_BYTES[addr_type + ('_test' if testnet else '')]


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
    raw = Base58.check_decode(xpub)
    return raw[-33:].hex()


def xpub_to_uncompressed_pk(xpub):
    """
    Derive an uncompressed public key from an xpub. Let the excellent bip32utils library create the point from the xpub.
    :param xpub: Base58 encoded xpub.
    :return: Hex string uncompressed public key.
    """
    ec_point = BIP32Key.fromExtendedKey(xpub).K.pubkey.point

    def hx(i): return hex(i)[2:]

    return '04' + hx(ec_point.x()) + hx(ec_point.y())


def pk_to_p2pkh_addr(pk, testnet=False):
    """
    Compressed public key (hex string) -> p2pkh address. 'Legacy Bitcoin address.'
    """
    pk_bytes = bytes.fromhex(pk)
    assert is_compressed_pk(pk_bytes), "Only use compressed public keys please."
    prefix = _prefix_bytes('p2pkh', testnet=testnet)
    return Base58.check_encode(prefix + hash160_bytes(pk_bytes))


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
    return kc.digest()[-20:].hex()


def pk_to_p2wpkh_in_p2sh_addr(pk, testnet=False):
    """
    Compressed public key (hex string) -> p2wpkh nested in p2sh address. 'SegWit address.'
    """
    pk_bytes = bytes.fromhex(pk)
    assert is_compressed_pk(pk_bytes), \
        "Only compressed public keys are compatible with p2sh-p2wpkh addresses. See BIP49."

    # Script sig is just PUSH(20){hash160(cpk)}
    push_20 = bytes.fromhex("0014")
    script_sig = push_20 + hash160_bytes(pk_bytes)

    # Address is then prefix + hash160(script_sig)
    prefix = _prefix_bytes('p2sh', testnet=testnet)
    address = Base58.check_encode(prefix + hash160_bytes(script_sig))
    return address


def pks_to_p2sh_multisig_addr(m, *pks):
    """
    :param m: The 'm' in m-of-n; the number of required signatures.
    :param pks: The public keys involved in the multisig. `len(pks) == n` in m-of-n.
    :return: A base 58 encoded address. (The p2sh address prefix + the hash of the redeem script.)
    """
    assert len(pks) <= 20, "keys passed to OP_CHECKMULTISIG <= 20"
    pks = sorted(pks)
    push_pks = reduce(lambda a, b: a + push_bytes(b), map(bytes.fromhex, pks), b'')
    n = op_n(len(pks))  # The 'n' part of m-of-n
    # Format is <OP_{M required}> <A pubkey> ... <N pubkey> <OP_{N keys}> <OP_CHECKMULTISIG>
    redeem_script = op_n(m) + push_pks + n + OP_CHECKMULTISIG
    assert len(redeem_script) <= 500, "Spending script is at most 500 bytes (it is valid /and/ standard)"
    return Base58.check_encode(_prefix_bytes("p2sh") + hash160_bytes(redeem_script))


def compress_pk(uncompressed_pk):
    """
    Uncompressed public key (hex string) -> compressed public key (hex string). Public key is (04, x, y) where 04 is a
    flag & x, y are the x, y elliptic curve coordinates. Compressed key is (02 + y's parity, x).
    """
    pk_bytes = bytes.fromhex(uncompressed_pk)
    assert is_uncompressed_pk(pk_bytes), "Provided key is uncompressed."
    pk_bytes = pk_bytes[1:]  # Remove the x04 prefix
    x, y = pk_bytes[:32], pk_bytes[32:]  # Split out the x, y ec points
    parity_flag = (b'\x03' if int(y.hex(), 16) & 1 else b'\x02')
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

