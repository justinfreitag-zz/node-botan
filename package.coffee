name: 'botan'
author: 'Justin Freitag'
description: 'Fully asynchronous Botan wrapper with RSA/public-key, cipher, hash, mac, codec, PBKDF, rnd support'
version: '0.0.1'
bin:
  random: './bin/random'
main: 'build/Release/botan'
dependencies:
  optimist: '~0.3'
devDependencies:
  mocha: '~0.11'
  should: '~0.6'
scripts:
  test: 'mocha -t 30000 -R list -r should test/node-botan-test'
engines:
  node: '~0.6'
private: on

