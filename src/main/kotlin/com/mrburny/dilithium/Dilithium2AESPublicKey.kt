package com.mrburny.dilithium

import com.mrburny.OQSProvider
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams
import java.security.PublicKey

class Dilithium2AESPublicKey(
    @Transient
    private val publicKey: ByteArray
) : PublicKey {

    override fun getAlgorithm(): String = OQSProvider.DILITHIUM2_AES_ALGORITHM_NAME

    override fun getFormat(): String = "X.509"

    override fun getEncoded(): ByteArray {
        val algorithmIdentifier = AlgorithmIdentifier(ASN1ObjectIdentifier(OQSProvider.DILITHIUM2_AES_OID))
        return SubjectPublicKeyInfo(algorithmIdentifier, publicKey).encoded
    }

    fun getKeyContent(): ByteArray = this.publicKey

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Dilithium2AESPublicKey

        if (!publicKey.contentEquals(other.publicKey)) return false

        return true
    }

    override fun hashCode(): Int {
        return publicKey.contentHashCode()
    }


}