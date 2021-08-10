package com.mrburny.dilithium

import com.mrburny.OQSProvider
import java.security.PublicKey

class Dilithium2AESPublicKey(
    @Transient
    private val publicKey: ByteArray
) : PublicKey {

    override fun getAlgorithm(): String = OQSProvider.DILITHIUM2_AES_ALGORITHM_NAME

    override fun getFormat(): String = "X.509"

    override fun getEncoded(): ByteArray {
        return publicKey
    }
}