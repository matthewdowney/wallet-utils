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

    def test_compress_pk(self):
        """
        Use bip49's test vector, which incidentally mentions these values.
        """
        unc_pk = "04a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f3010ba699877871e188285d8c36e320eb08311d8aecf27ff8971bc7fde240bfd"
        self.assertEqual(compress_pk(unc_pk), "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f")

    def test_p2sh_multisig(self):
        three_pks = [
            "0411ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e83",
            "046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187",
            "04a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700c9f4d4df849323dac06cf3bd6458cd"
        ]
        self.assertEqual(pks_to_p2sh_multisig_addr(2, *three_pks), "3Jdaaix9j8sc1YbTzLSvrqTmm5jmTeMC47")
        self.assertEqual(pks_to_p2sh_multisig_addr(3, *three_pks), "33TRzZN758aJsmJGAkBgnXxj4PtPtMuMWc")
        self.assertEqual(pks_to_p2sh_multisig_addr(2, *three_pks), pks_to_p2sh_multisig_addr(2, *reversed(three_pks)),
                         msg="Should automatically sort public keys")

        compressed = sorted(map(compress_pk, three_pks))
        self.assertEqual(pks_to_p2sh_multisig_addr(2, *compressed), "39NqPn6kKbiE8ojF9D71mGCGwfGN3gYAdo")


    @staticmethod
    def bip49_xpub():
        """
        BIP49's test vector only gives an xpriv, so use the excellent bip32utils library to return that xpriv -> xpub.
        """
        xpriv = "tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY"
        return BIP32Key.fromExtendedKey(xpriv, public=False).ExtendedKey(private=False)


if __name__ == '__main__':
    unittest.main()
