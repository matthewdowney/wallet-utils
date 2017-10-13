import unittest

from xpub.crypto import *


class TestCryptoMethods(unittest.TestCase):
    """
    Wherever possible, test vectors from BIPs are used.
    """

    def test_xpub_to_child_xpub(self):
        """
        BIP32 test case for getting the child derivation of an xpub.
        """
        root = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
        child1 = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
        self.assertEqual(xpub_to_child_xpub(root, 1), child1)
        self.assertEqual(xpub_at_path(root, 1), child1)

    def test_xpub_at_path(self):
        """
        BIP32 test case with a more involved path.
        """
        root = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
        child2 = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
        child2_1000000000 = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        self.assertEqual(xpub_to_child_xpub(root, 2), child2)
        self.assertEqual(xpub_at_path(root, 2), child2)

        self.assertEqual(xpub_at_path(root, 2, 1000000000), child2_1000000000)
        self.assertEqual(xpub_to_child_xpub(xpub_to_child_xpub(root, 2), 1000000000), child2_1000000000)

    def test_xpub_to_pk(self):
        xpub = self.bip49_xpub()
        recv0 = xpub_at_path(xpub, 0, 0)  # first receive address
        self.assertEqual(xpub_to_pk(recv0), "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f")

    def test_xpub_to_uncompressed(self):
        """
        xpub is for the compressed public key 03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f.
        """
        xpub = self.bip49_xpub()
        recv0 = xpub_at_path(xpub, 0, 0)  # first receive address
        unc_pk = "04a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f3010ba699877871e188285d8c36e320eb08311d8aecf27ff8971bc7fde240bfd"
        self.assertEqual(xpub_to_uncompressed_pk(recv0), unc_pk)

    def test_pk_to_bitcoin_address(self):
        """
        p2pkh address. Test case from https://bitcore.io/api/lib/public-key
        """
        pk = "030589ee559348bd6a7325994f9c8eff12bd5d73cc683142bd0dd1a17abc99b0dc"
        self.assertEqual(pk_to_p2pkh_addr(pk), "1KbUJ4x8epz6QqxkmZbTc4f79JbWWz6g37")
        self.assertEqual(pk_to_p2pkh_addr(pk, testnet=True), "mz7Rb837TrRMBxSNV8ZqRysS1JCDPWFLCc")

    def test_bip49_segwit_addr(self):
        bip49pk = "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        # BIP49 test case
        self.assertEqual(pk_to_p2wpkh_in_p2sh_addr(bip49pk, testnet=True), "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2")
        self.assertEqual(pk_to_p2wpkh_in_p2sh_addr(bip49pk), "36NvZTcMsMowbt78wPzJaHHWaNiyR73Y4g")

    def test_pk_to_ethereum_addr(self):
        """
        Using examples from:
        https://kobl.one/blog/create-full-ethereum-keypair-and-address/#derive-the-ethereum-address-from-the-public-key
        """
        pub_key = "04836b35a026743e823a90a0ee3b91bf615c6a757e2b60b9e1dc1826fd0dd16106f7bc1e8179f665015f43c6c81f39062fc2086ed849625c06e04697698b21855e"
        address = "0bed7abd61247635c1973eb38474a2516ed1d884"
        self.assertEqual(pk_to_ethereum_addr(pub_key), address)

    @staticmethod
    def bip49_xpub():
        """
        BIP49's test vector only gives an xpriv, so use the excellent bip32utils library to return that xpriv -> xpub.
        """
        xpriv = "tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY"
        return BIP32Key.fromExtendedKey(xpriv, public=False).ExtendedKey(private=False)


if __name__ == '__main__':
    unittest.main()
