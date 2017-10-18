import unittest

from xpub.btc_script import *


class TestBtcScriptFunctions(unittest.TestCase):

    def test_op_n(self):
        # Respective inputs & outputs
        self.assertListEqual(list(map(op_n, [-1, 1, 2, 16])),
                             [b'\x4f', OP_1_TRUE, b'\x52', b'\x60'])

    def test_op_n_lt(self):
        with self.assertRaises(AssertionError):
            op_n(-2)

    def test_op_n_gt(self):
        with self.assertRaises(AssertionError):
            op_n(17)

    def test_push_n(self):
        self.assertListEqual(list(map(push_n, [1, 5, 10, 16, 20, 75])),
                             [b'\x01', b'\x05', b'\x0a', b'\x10', b'\x14', b'\x4b'])

    def test_push_n_lt(self):
        with self.assertRaises(AssertionError):
            push_n(0)

    def test_push_n_gt(self):
        with self.assertRaises(AssertionError):
            push_n(76)

    def test_push_bytes(self):
        byte_data = b"pushme"
        push_byte_data = push_bytes(byte_data)
        self.assertEqual(len(push_byte_data), len(byte_data) + 1)
        self.assertEqual(push_byte_data[0], len(byte_data))
        self.assertEqual(push_byte_data[1:], byte_data)

if __name__ == '__main__':
    unittest.main()
