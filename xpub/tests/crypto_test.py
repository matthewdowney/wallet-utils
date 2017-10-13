import unittest

from xpub.crypto import *


class TestCryptoMethods(unittest.TestCase):
    """
    Test vectors from BIPs are used wherever possible. Naming convention for test methods is
    `test_bip{bip#}_{testvector#}`, e.g. `def test_bip_32_1(self): ...`. Extra _number suffixes denote bulleted sub-test
    vectors in a BIP.
    """

    # Test xpub_to_child_xpub, xpub_at_path
    def test_bip32_1_3(self):
        root = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
        child1 = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
        self.assertEqual(xpub_to_child_xpub(root, 1), child1)
        self.assertEqual(xpub_at_path(root, 1), child1)

    # Test xpub_to_child_xpub, xpub_at_path
    def test_bip32_1_5_and_6(self):
        root = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
        child2 = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
        child2_1000000000 = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        self.assertEqual(xpub_to_child_xpub(root, 2), child2)
        self.assertEqual(xpub_at_path(root, 2), child2)

        self.assertEqual(xpub_at_path(root, 2, 1000000000), child2_1000000000)
        self.assertEqual(xpub_to_child_xpub(xpub_to_child_xpub(root, 2), 1000000000), child2_1000000000)

    # Test xpub_to_pk
    def test_bip_49_1(self):
        """
        BIP 49 is the only one defining test vectors for x*keys to public keys. They give an xpriv, so we'll use the
        excellent bip32utils library to go test xpriv -> test xpub -> test path -> public key and make sure it matches
        the test vector.
        """
        xpriv = "tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY"
        xpub = BIP32Key.fromExtendedKey(xpriv, public=False).ExtendedKey(private=False)
        recv0 = xpub_at_path(xpub, 0, 0)  # first receive address
        self.assertEqual(xpub_to_pk(recv0), "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f")


if __name__ == '__main__':
    unittest.main()
