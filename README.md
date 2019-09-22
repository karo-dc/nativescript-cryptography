# Nativescript Cryptography

A simple plugin for asymmetric keys operations.

## Installation

tns plugin add nativescript-cryptography

## Usage

import { Cryptography } from "nativescript-cryptography";

@param1: random tag string
@param2: size of key
@param3: save in secure storage (optional)

const keyPair = cryptography.generateRsaPrivateKey(RsaPrivateKeyTag, RsaKeySize, true);

## License

MIT
