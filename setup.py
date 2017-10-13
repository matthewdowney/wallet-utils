from distutils.core import setup

setup(
    name='xpub-utils',
    version='0.0.0',
    packages=['xpub'],
    url='',
    license='MIT',
    author='Matthew Downey',
    author_email='matthewdowney20@gmail.com',
    description='Utilities for dealing with extended public keys (xpubs) in HD crypto wallets. '
                'Wraps the excellent bip32utils library, which does the ECDSA & key derivation heavy lifting, to '
                'provide a function wrappers & support different address types.',
    requires=['bip32utils', 'pysha3']
)
