package com.mrburny.dilithium

import com.mrburny.OQSProvider
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.Security
import java.security.Signature

class Dilithium2AESSignatureSpiTest {

    init {
        Security.addProvider(OQSProvider)
    }

    private val messageBytes = "This is the message to be signed.".toByteArray()

    @Test
    fun `Dilithium2-AES full process keygen-sign-verify sanity check`() {
        val keyPairGenerator = KeyPairGenerator.getInstance("Dilithium2-AES", "OQS")
        val keyPair = keyPairGenerator.generateKeyPair()

        var signature = Signature.getInstance("Dilithium2-AES", "OQS")
        signature.initSign(keyPair.private)
        signature.update(messageBytes, 0, messageBytes.size)
        val signatureBytes = signature.sign()

        signature = Signature.getInstance("Dilithium2-AES", "OQS")
        signature.initVerify(keyPair.public)
        signature.update(messageBytes, 0, messageBytes.size)
        assertTrue(signature.verify(signatureBytes))
    }
}
