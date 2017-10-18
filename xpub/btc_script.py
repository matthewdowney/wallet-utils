"""
Utilities for Bitcoin scripting--works entirely with byte values.
"""

OP_CHECKMULTISIG = b'\xae'
OP_0 = b'\x00'
OP_1_TRUE = b'\x51'
OP_HASH160 = b'\xa9'
OP_EQUAL = b'\x87'


def op_n(int_n):
    """
    OP_N where N is a number, an OP_N represents that number.
    """
    assert int_n == -1 or 1 <= int_n <= 16, "N in OP_N is in the set: {-1, [1-16]}"
    op_1 = int(OP_1_TRUE.hex(), 16)  # Fist number coded op is 1
    hex_val = hex(op_1 + int_n - 1)  # Do integer addition to find the right op code
    return bytes.fromhex(hex_val[2:])  # Reencode as byte


def push_n(int_n):
    """
    Opcode to push some number of bytes.
    """
    assert 1 <= int_n <= 75, "Can't push more than 75 bytes with PUSH(N) in a single byte."
    n = hex(int_n)[2:]
    n = n if len(n) == 2 else '0' + n
    return bytes.fromhex(n)


def push_bytes(byte_data):
    """
    A push opcode for the number of bytes provided, and then the provided bytes.
    """
    return push_n(len(byte_data)) + byte_data
