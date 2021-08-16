package com.mrburny.dilithium

import com.mrburny.OQSProvider
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import java.security.PrivateKey

/**
 * Implementation of Dilithium private key with BCSphincs256PrivateKey as a reference implementation.
 *
 * PKCS #8 format structure:
 * PrivateKeyInfo ::= SEQUENCE {
 *      version             INTEGER,
 *      privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
 *      privateKey          OCTET STRING,
 *      attributes          IMPLICIT Attributes OPTIONAL
 * }
 * PrivateKeyAlgorithmIdentifier ::= SEQUENCE {
 *      algorithm           OBJECT IDENTIFIER,
 *      parameters          ANY DEFINED BY algorithm OPTIONAL
 * }
 *
 * All OPTIONAL attributes will be omitted for the time being.
 * For the sake of reliability and delivery of this feature in time we will use ASN.1-parsing functionality from the bouncy castle library.
 */
class Dilithium2AESPrivateKey(
    @Transient
    val content: ByteArray
) : PrivateKey {

    companion object {
        private const val DILITHIUM_PRIVATE_KEY_SIZE: Int = 2528
    }

    init {
        if (content.size != DILITHIUM_PRIVATE_KEY_SIZE) {
            throw IllegalStateException("Private key size should be $DILITHIUM_PRIVATE_KEY_SIZE")
        }
    }

    override fun getAlgorithm(): String = OQSProvider.DILITHIUM2_AES_ALGORITHM_NAME

    override fun getFormat(): String = "PKCS#8"

    override fun getEncoded(): ByteArray {
        val algorithmIdentifier = AlgorithmIdentifier(ASN1ObjectIdentifier(OQSProvider.DILITHIUM2_AES_OID))
        return PrivateKeyInfo(algorithmIdentifier, DEROctetString(content)).encoded
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Dilithium2AESPrivateKey

        if (!content.contentEquals(other.content)) return false

        return true
    }

    override fun hashCode(): Int {
        return content.contentHashCode()
    }
}
