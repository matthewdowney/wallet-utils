from functools import reduce

try:
    from bip32utils import BIP32Key
except ImportError:
    raise ImportError("Please install the bip32utils project: $ pip install git+https://github.com/prusnak/bip32utils")

# BIP32 Keys are specified as hardened (derived using the private key) if their index is >= 2**31. These utils are for
# xpubs only--no private keys--so all indexes must be < MAX_IDX
MAX_IDX = 0x80000000


def xpub_to_child_xpub(xpub, idx):
    """
    Get the child xpub for a given xpub and index. E.g. if `xp` is the xpub for m/44'/0'/0', then
    `xpub_to_child_xpub(xp, i)` will give the xpub corresponding to m/44'/0'/0'/i.
    :param xpub: Base58 encoded xpub.
    :param idx: Integer, non-hardened index (idx < 2**31).
    :return: Base58 encoded xpub.
    """
    assert idx < MAX_IDX, "Indexes >= 2^31 must be derived as hardened, which is not possible with an xpub."
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
    Derive a compresses public key from an xpub.
    :param xpub: Base58 encoded xpub.
    :return: Hex string compressed public key.
    """
    return BIP32Key.fromExtendedKey(xpub).PublicKey().hex()
