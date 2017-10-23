import itertools
import unittest

from wallet_utils.crypto import *


class LongRunningTests(unittest.TestCase):
    """
    Tests that require some amount of time to complete. Separated to reduce friction of continuously running tests while
    developing, which should be encouraged at all costs. Should still be run before any deployment.
    """

    def test_xpub_to_uncompressed_consistent(self):
        """
        Take some xpub, get a ton of indexes, and make sure that for each index the uncompressed public key compresses
        to the compressed public key for the xpub.
        """
        xpub = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

        # Pick num indexes from the beginning, middle, and end of the possible range
        num = 500
        print("Generating {} xpubs distributed across the range {} to {}".format(num * 3, 0, 2 ** 31))
        idxs = itertools.chain(range(0, num), range(2 ** 30, (2 ** 30) + num), range((2 ** 31) - num, 2 ** 31))

        progress = 0
        for idx in idxs:
            xp = xpub_at_path(xpub, 0, idx)
            compressed, uncompressed = xpub_to_pk(xp), xpub_to_uncompressed_pk(xp)
            self.assertEqual(compressed, compress_pk(uncompressed))

            progress += 1
            if progress % 15 == 0:
                print("{}% done...".format(round((float(progress) * 100) / (num * 3), 0)))


if __name__ == '__main__':
    unittest.main()
