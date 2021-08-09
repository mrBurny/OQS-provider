package com.mrburny

import java.security.Provider

object OQSProvider : Provider("OQS", 1.0, "Provider of OQS implementations of PQ algorithms") {
    init {
        put("KeyPairGenerator.Dilithium2-AES", "com.mrburny.dilithium.Dilithium2AESKeyPairGeneratorSpi")
        put("Signature.Dilithium2-AES", "com.mrburny.dilithium.Dilithium2AESSignatureSpi")
    }

    const val DILITHIUM2_AES_ALGORITHM_NAME = "Dilithium2-AES"
    const val DILITHIUM2_AES_OID = "1.3.6.1.4.1.2.267.11.4.4"
}