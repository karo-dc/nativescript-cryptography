import KeyPairGenerator = java.security.KeyPairGenerator;
import PrivateKeyEntry = java.security.KeyStore.PrivateKeyEntry;
import KeyStore = java.security.KeyStore;
import PrivateKey = java.security.PrivateKey;
import PublicKey = java.security.PublicKey;
import KeyPair = java.security.KeyPair;
import Signature = java.security.Signature;
import Cipher = javax.crypto.Cipher;
import Base64 = android.util.Base64;
import { AndroidKeyStore } from './configs/constants';
import StringWriter = java.io.StringWriter;

declare const org: any;
const KeyGenParameterSpec = (android.security as any).keystore
  .KeyGenParameterSpec;
const KeyProperties = (android.security as any).keystore.KeyProperties;

export enum RsaHashAlgorithm {
  SHA1 = 'SHA1withRSA',
  SHA224 = 'SHA224withRSA',
  SHA256 = 'SHA256withRSA',
  SHA384 = 'SHA384withRSA',
  SHA512 = 'SHA512withRSA',
}

export enum RsaEncryptionAlgorithm {
  OAEP_SHA1 = 'RSA/NONE/OAEPWithSHA-1AndMGF1Padding',
  OAEP_SHA224 = 'RSA/NONE/OAEPWithSHA-224AndMGF1Padding',
  OAEP_SHA256 = 'RSA/NONE/OAEPWithSHA-256AndMGF1Padding',
  OAEP_SHA384 = 'RSA/NONE/OAEPWithSHA-384AndMGF1Padding',
  OAEP_SHA512 = 'RSA/NONE/OAEPWithSHA-512AndMGF1Padding',
}

export class Cryptography {
  public generateRsaPrivateKey(
    tag: string,
    keySize: number,
    isSaveInSecureStorage?: boolean,
  ): RsaKey {
    const keyGenerator = isSaveInSecureStorage
      ? KeyPairGenerator.getInstance(
          KeyProperties.KEY_ALGORITHM_RSA,
          AndroidKeyStore,
        )
      : KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA);

    const params = new KeyGenParameterSpec.Builder(
      tag,
      KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_SIGN,
    )
      .setDigests([KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256])
      .setEncryptionPaddings([KeyProperties.ENCRYPTION_PADDING_RSA_OAEP])
      .setSignaturePaddings([KeyProperties.SIGNATURE_PADDING_RSA_PKCS1])
      .setKeySize(keySize)
      .build();
    keyGenerator.initialize(params);
    return new RsaKey(keyGenerator.generateKeyPair());
  }

  public loadExistingRsaPrivateKeyByTag(tag: string): RsaKey {
    const keyStore = KeyStore.getInstance(AndroidKeyStore);
    keyStore.load(null);
    const entry = keyStore.getEntry(tag, null) as PrivateKeyEntry;
    const privKey = entry.getPrivateKey();
    const cert = entry.getCertificate();
    const pubKey = cert.getPublicKey();
    return new RsaKey(new KeyPair(pubKey, privKey));
  }

  public encryptViaPublicKey(
    data: string,
    rsaKey: RsaKey,
    alg: RsaEncryptionAlgorithm,
  ): string {
    const textToEncryptBytes = new java.lang.String(data).getBytes();
    const cipher = Cipher.getInstance(alg);
    cipher.init(Cipher.ENCRYPT_MODE, rsaKey.getPublicKey());
    const encryptedByteData = cipher.doFinal(textToEncryptBytes);
    const textEncryptedBase64 = Base64.encodeToString(
      encryptedByteData,
      Base64.DEFAULT,
    );
    return textEncryptedBase64;
  }

  public decryptViaPrivateKey(
    encryptedData: string,
    pair: RsaKey,
    alg: RsaEncryptionAlgorithm,
  ): string {
    const bytes = Base64.decode(encryptedData, Base64.NO_WRAP);
    const cipher = Cipher.getInstance(alg);
    cipher.init(Cipher.DECRYPT_MODE, pair.getPrivateKeyValue());
    const decryptedByteData = cipher.doFinal(bytes);
    return new java.lang.String(decryptedByteData).toString();
  }

  public sign(
    data: string,
    key: RsaKey,
    alg: RsaHashAlgorithm,
    returnAsBase64?: boolean,
  ): ArrayBuffer | string {
    const signEngine = Signature.getInstance(alg);
    signEngine.initSign(key.getPrivateKeyValue());
    signEngine.update(this.stringToByteArray(data));
    const sign = signEngine.sign();
    if (returnAsBase64) {
      return Base64.encodeToString(sign, Base64.NO_WRAP);
    }
    return new Uint8Array(sign).buffer;
  }

  private stringToByteArray(data: string) {
    return new java.lang.String(data).getBytes('UTF-8');
  }
}

export class RsaKey {
  private keyPair: KeyPair;

  constructor(data: KeyPair) {
    this.keyPair = data;
  }

  public getPrivateKeyValue(): PrivateKey {
    return this.keyPair.getPrivate();
  }

  public getPublicKey(): PublicKey {
    return this.keyPair.getPublic();
  }

  public getBase64PublicKey(): string {
    const stringWriter = new StringWriter();
    const pemWriter = new org.bouncycastle.util.io.pem.PemWriter(stringWriter);
    const publicKeyPKCS1 = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(
      this.getPublicKey().getEncoded(),
    )
      .parsePublicKey()
      .getEncoded();
    const pemObject = new org.bouncycastle.util.io.pem.PemObject(
      'RSA PUBLIC KEY',
      publicKeyPKCS1,
    );
    pemWriter.writeObject(pemObject);
    pemWriter.close();
    const key = stringWriter
      .toString()
      .replace('-----BEGIN RSA PUBLIC KEY-----\n', '')
      .replace('\n-----END RSA PUBLIC KEY-----\n', '')
      .trim();
    return key;
  }
}
