from distutils.core import setup

setup(
    name='wallet-utils',
    version='0.0.0',
    packages=['wallet_utils'],
    url='',
    license='MIT',
    author='Matthew Downey',
    author_email='matthewdowney20@gmail.com',
    description='Utilities for dealing with crypto wallets (support for HD wallets). Makes use of the excellent '
                'bip32utils library, which does the EC crypto key derivation heavy lifting.',
    requires=['bip32utils', 'pysha3']
)
