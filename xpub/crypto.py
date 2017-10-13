import hashlib
from functools import reduce
from hashlib import sha256

try:
    from bip32utils import BIP32Key, Base58
except ImportError:
    BIP32Key = Base58 = None
    raise ImportError("Please install the bip32utils project: $ pip install git+https://github.com/prusnak/bip32utils")

try:
    # noinspection PyPackageRequirements
    import sha3

    def keccak_256(): return sha3.keccak_256()
except Exception:
    raise ImportError("Need the pysha3 to use Ethereum's special keccak variation (which doesn't conform to the "
                      "eventual sha3 standard: $ pip install pysha3")

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
    assert compressed_pk(pk_bytes), "Only use compressed public keys please."
    prefix = ADDR_PREFIX_BYTES['p2pkh' + ('_test' if testnet else '')]
    return Base58.check_encode(prefix + hash160_bytes(pk_bytes))


def pk_to_ethereum_addr(uncompressed_pk):
    """
    Uncompressed public key (hex string) -> Ethereum address.
    """
    pk_bytes = bytes.fromhex(uncompressed_pk)
    assert len(pk_bytes) == 65 and pk_bytes.startswith(b"\x04"), \
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
    assert compressed_pk(pk_bytes), "Only compressed public keys are compatible with p2sh-p2wpkh addresses. See BIP49."

    # Script sig is just PUSH(20){hash160(cpk)}
    push_20 = bytes.fromhex("0014")
    script_sig = push_20 + hash160_bytes(pk_bytes)

    # Address is then prefix + hash160(script_sig)
    prefix = ADDR_PREFIX_BYTES['p2sh' + ('_test' if testnet else '')]
    address = Base58.check_encode(prefix + hash160_bytes(script_sig))
    return address


def hash160_bytes(byte_input):
    """
    Type is bytes -> bytes.
    """
    return hashlib.new('ripemd160', sha256(byte_input).digest()).digest()


def compressed_pk(pk_bytes):
    """
    Compressed public keys are 32 bytes of the pk prefixed with a parity byte.
    :return True for valid compressed format.
    """
    return len(pk_bytes) == 33 and (pk_bytes.startswith(b"\x02") or pk_bytes.startswith(b"\x03"))
