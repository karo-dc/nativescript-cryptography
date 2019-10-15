import { Common } from './cryptography.common';

export declare enum RsaHashAlgorithm {
  SHA1,
  SHA224,
  SHA256,
  SHA384,
  SHA512,
}

export declare enum RsaEncryptionAlgorithm {
  RAW,
  PKCS1,
  OAEP_SHA1,
  OAEP_SHA224,
  OAEP_SHA256,
  OAEP_SHA384,
  OAEP_SHA512,
}

export declare class Cryptography {
  public generateRsaPrivateKey(
    tag: string,
    keySize: number,
    isSaveInSecureStorage?: boolean,
  ): RsaKey;
  public loadExistingRsaPrivateKeyByTag(tag: string): RsaKey;
  public removeRsaPrivateKeyByTag(tag: string);
  public sign(
    data: string,
    privateKey: RsaKey,
    alg: RsaHashAlgorithm,
    returnAsBase64?: boolean,
  ): ArrayBuffer | string;
  public encryptViaPublicKey(
    data: string,
    key: RsaKey,
    alg: RsaEncryptionAlgorithm,
  ): string;
  public decryptViaPrivateKey(
    encryptedData: string,
    key: RsaKey,
    alg: RsaEncryptionAlgorithm,
  ): string;
}

export declare class RsaKey {
  public getBase64PublicKey(): string;
}
