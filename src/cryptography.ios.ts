export enum RsaHashAlgorithm {
  SHA1 = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1,
  SHA224 = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224,
  SHA256 = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
  SHA384 = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384,
  SHA512 = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512,
}

export enum RsaEncryptionAlgorithm {
  RAW = kSecKeyAlgorithmRSAEncryptionRaw,
  PKCS1 = kSecKeyAlgorithmRSAEncryptionPKCS1,
  // RSA Encryption OAEP
  OAEP_SHA1 = kSecKeyAlgorithmRSAEncryptionOAEPSHA1,
  OAEP_SHA224 = kSecKeyAlgorithmRSAEncryptionOAEPSHA224,
  OAEP_SHA256 = kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
  OAEP_SHA384 = kSecKeyAlgorithmRSAEncryptionOAEPSHA384,
  OAEP_SHA512 = kSecKeyAlgorithmRSAEncryptionOAEPSHA512,
}

export class Cryptography {
  public generateRsaPrivateKey(
    tag: string,
    keySize: number,
    isSaveInSecureStorage?: boolean,
  ): RsaKey {
    try {
      const privateKeyAttrs = NSMutableDictionary.new();
      if (isSaveInSecureStorage) {
        privateKeyAttrs.setValueForKey(kCFBooleanTrue, kSecAttrIsPermanent);
      }
      privateKeyAttrs.setValueForKey(tag, kSecAttrApplicationTag);
      privateKeyAttrs.setValueForKey(kCFBooleanTrue, kSecAttrCanEncrypt);

      const generalAttrs = NSMutableDictionary.alloc().init();
      generalAttrs.setValueForKey(kSecAttrKeyTypeRSA, kSecAttrKeyType);
      generalAttrs.setValueForKey(
        NSNumber.numberWithInt(keySize),
        kSecAttrKeySizeInBits,
      );
      generalAttrs.setObjectForKey(privateKeyAttrs, kSecPrivateKeyAttrs);

      const error = new interop.Reference<NSError>();
      const privateKey = SecKeyCreateRandomKey(generalAttrs, error);
      if (privateKey === null) {
        throw error;
      } else {
        return new RsaKey(privateKey);
      }
    } catch (error) {
      console.error('Rsa.generateKey failed with error ' + error);
      return null;
    }
  }

  public loadExistingRsaPrivateKeyByTag(tag: string): RsaKey {
    if (tag == null) {
      return null;
    }
    const attrs = NSMutableDictionary.alloc().init();
    attrs.setValueForKey(kSecClassKey, kSecClass);
    attrs.setValueForKey(kSecAttrKeyClassPrivate, kSecAttrKeyClass);
    attrs.setValueForKey(kSecAttrKeyTypeRSA, kSecAttrKeyType);
    attrs.setValueForKey(2048, kSecAttrKeySizeInBits);
    attrs.setValueForKey(tag, kSecAttrApplicationTag);
    attrs.setValueForKey(true, kSecReturnRef);

    const privateKeyRef = new interop.Reference<any>();
    const status = SecItemCopyMatching(attrs, privateKeyRef);
    return new RsaKey(privateKeyRef.value);
  }

  public encryptViaPublicKey(
    data: string,
    publicKey: RsaKey,
    alg: RsaEncryptionAlgorithm,
  ): string {
    const rawData = this.stringToNSData(data);
    const error = new interop.Reference<NSError>();
    const encryptedData = SecKeyCreateEncryptedData(
      publicKey,
      alg,
      rawData,
      error,
    );
    return encryptedData.base64Encoding();
  }

  public decryptViaPrivateKey(
    encryptedData: string,
    privateKey: RsaKey,
    alg: RsaEncryptionAlgorithm,
  ): string {
    const nsData: NSData = NSData.alloc().initWithBase64EncodedStringOptions(
      encryptedData,
      null,
    );

    const error = new interop.Reference<NSError>();
    const plaintextData = SecKeyCreateDecryptedData(
      privateKey.getPrivateKeyValue(),
      alg,
      nsData,
      error,
    );
    console.info('ERROR: ', error.value);
    return this.NSDataToString(plaintextData).toString();
  }

  public sign(
    data: string,
    privateKey: RsaKey,
    alg: RsaHashAlgorithm,
    returnAsBase64?: boolean,
  ): ArrayBuffer | string {
    let error = new interop.Reference<NSError>();
    try {
      const nsData = this.stringToNSData(data);
      const signature = SecKeyCreateSignature(
        privateKey.getPrivateKeyValue(),
        alg,
        nsData,
        error,
      );

      if (error && error.value) {
        console.error('Rsa.sign failed with error ' + error);
        return null;
      }
      if (returnAsBase64) {
        return signature.base64Encoding();
      }
      return interop.bufferFromData(signature);
    } catch (error) {
      console.error('Rsa.sign failed with error ' + error);
      return null;
    }
  }

  private stringToNSData(data: string): NSData {
    return NSString.stringWithString(data).dataUsingEncoding(
      NSUTF8StringEncoding,
    );
  }

  private NSDataToString(data: NSData): NSString {
    return NSString.alloc().initWithDataEncoding(data, NSUTF8StringEncoding);
  }
}

export class RsaKey {
  private privateKeyValue: any;

  constructor(privateKey: any) {
    this.privateKeyValue = privateKey;
  }

  public getPrivateKeyValue(): any {
    return this.privateKeyValue;
  }

  public getPublicKey(): any {
    return SecKeyCopyPublicKey(this.privateKeyValue);
  }

  public getPrivateKeyData(): any {
    let error: interop.Reference<NSError>, privateKeyData: NSData;
    try {
      privateKeyData = SecKeyCopyExternalRepresentation(
        this.privateKeyValue,
        error,
      );
      console.error('RsaKey.getPrivateKey Error ' + error);
      console.info('RsaKey.getPrivateKey Success ' + privateKeyData);
      return privateKeyData;
    } catch (error) {
      console.error('RsaKey.getPrivateKey failed with error ' + error);
      return null;
    }
  }

  public getBase64PublicKey(): string {
    let publicKeyRef: interop.Reference<any>,
      error: interop.Reference<NSError>,
      publicKeyData: NSData;

    try {
      publicKeyRef = SecKeyCopyPublicKey(this.privateKeyValue);
      publicKeyData = SecKeyCopyExternalRepresentation(publicKeyRef, error);
      const publicKeyBase64 = publicKeyData.base64Encoding();
      if (error && error.value) {
        throw error.value.localizedDescription;
      }
      return publicKeyBase64;
    } catch (error) {
      console.error('RsaKey.getPublicKey failed with error ' + error);
      return null;
    }
  }
}
