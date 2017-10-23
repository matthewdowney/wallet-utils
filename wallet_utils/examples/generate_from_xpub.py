from wallet_utils.crypto import *

# Represents path m/44'/0'/0'
xpub = "xpub6Bkc3FSaARtmARUFj6Ln224C2H8aHfxD1jVGz66REjN8KnoGJ7KF5f1S7shvZ7ii98DwLJ6ZakgDJgPdFR44aH87HqYDA8fm2GRj4FtC7f8"

i, step = 0, 10
while step < MAX_IDX:
    while i < step:
        derived = xpub_at_path(xpub, 0, i)  # Appends /0/i to the xpub's path (so we end with m/44'/0'/0'/0/i
        public_key = xpub_to_pk(derived)
        print(pk_to_p2pkh_addr(public_key))
        i += 1
    step += 10
    input("Press [enter] to load more")

print("If you pressed enter once per second, it would take you like six years to reach this line. Congrats.")
