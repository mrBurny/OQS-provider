package com.mrburny.dilithium

import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import java.security.InvalidKeyException
import java.security.Key
import java.security.KeyFactorySpi
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class Dilithium2AESKeyFactorySpi : KeyFactorySpi() {
    override fun engineGeneratePublic(keySpec: KeySpec?): PublicKey {
        if (keySpec == null || keySpec !is X509EncodedKeySpec) {
            throw InvalidKeySpecException("Unsupported key specification specification: ${keySpec?.javaClass}")
        }

        val encKey = keySpec.encoded
        return Dilithium2AESPublicKey(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(encKey)).publicKeyData.bytes)
    }

    override fun engineGeneratePrivate(keySpec: KeySpec?): PrivateKey {
        if (keySpec == null) {
            throw InvalidKeySpecException("Unsupported key specification: null")
        }
        if (keySpec !is PKCS8EncodedKeySpec) {
            throw InvalidKeySpecException("Unsupported key specification: ${keySpec.javaClass}")
        }

        val encKey = keySpec.encoded
        val privateKey = ASN1OctetString.getInstance(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(encKey)).parsePrivateKey()).octets
        return Dilithium2AESPrivateKey(privateKey)
    }

    override fun <T : KeySpec?> engineGetKeySpec(key: Key?, keySpec: Class<T>?): T {
        if (keySpec == null) {
            throw InvalidKeySpecException("Unsupported key specification type: ${keySpec?.javaClass}")
        }

        if (key is Dilithium2AESPrivateKey) {
            if (PKCS8EncodedKeySpec::class.java.isAssignableFrom(keySpec)) {
                return PKCS8EncodedKeySpec(key.encoded) as T
            }
        }

        if (key is Dilithium2AESPublicKey) {
            if (X509EncodedKeySpec::class.java.isAssignableFrom(keySpec)) {
                return X509EncodedKeySpec(key.encoded) as T
            }
        }

        throw InvalidKeySpecException("Unsupported key type: ${key?.javaClass}")
    }

    override fun engineTranslateKey(key: Key?): Key {
        if (key is Dilithium2AESPrivateKey || key is Dilithium2AESPublicKey) {
            return key
        }

        throw InvalidKeyException("Unsupported key type")
    }
}