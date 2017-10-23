# Root path m/44'/60'/0'
from wallet_utils.crypto import pk_to_ethereum_addr, xpub_to_uncompressed_pk, xpub_at_path

xpub = "xpub6Bkc3FSaARtmARUFj6Ln224C2H8aHfxD1jVGz66REjN8KnoGJ7KF5f1S7shvZ7ii98DwLJ6ZakgDJgPdFR44aH87HqYDA8fm2GRj4FtC7f8"
addresses = (pk_to_ethereum_addr(xpub_to_uncompressed_pk(xpub_at_path(xpub, 0, i))) for i in range(2**31))
for i in range(2**31):
    print("Path m/44'/60'/0'/0/{}".format(i))
    xp = xpub_at_path(xpub, 0, i)
    print("xpub   \t{}".format(xp))
    pk = xpub_to_uncompressed_pk(xp)
    print("pk     \t{}".format(pk))
    print("address\t0x{}".format(pk_to_ethereum_addr(pk)))
    input("")
