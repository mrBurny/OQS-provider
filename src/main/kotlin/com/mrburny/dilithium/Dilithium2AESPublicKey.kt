package com.mrburny.dilithium

import com.mrburny.OQSProvider
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import java.security.PublicKey

class Dilithium2AESPublicKey(
    @Transient
    val content: ByteArray
) : PublicKey {

    companion object {
        private const val DILITHIUM_PUBLIC_KEY_SIZE: Int = 1312
    }

    init {
        if (content.size != DILITHIUM_PUBLIC_KEY_SIZE) {
            throw IllegalStateException("Public key size should be $DILITHIUM_PUBLIC_KEY_SIZE")
        }
    }

    override fun getAlgorithm(): String = OQSProvider.DILITHIUM2_AES_ALGORITHM_NAME

    override fun getFormat(): String = "X.509"

    override fun getEncoded(): ByteArray {
        val algorithmIdentifier = AlgorithmIdentifier(ASN1ObjectIdentifier(OQSProvider.DILITHIUM2_AES_OID))
        return SubjectPublicKeyInfo(algorithmIdentifier, content).encoded
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Dilithium2AESPublicKey

        if (!content.contentEquals(other.content)) return false

        return true
    }

    override fun hashCode(): Int {
        return content.contentHashCode()
    }
}
