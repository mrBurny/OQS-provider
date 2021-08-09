package com.mrburny

import com.mrburny.dilithium.Dilithium2AESPrivateKey
import org.bouncycastle.util.encoders.Base64
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.openquantumsafe.Signature
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security

class SignatureDemo {
    @Test
    fun `should generate signature`() {
        val random = SecureRandom()
        val privateKeyBytes = ByteArray(2528)
        random.nextBytes(privateKeyBytes)

        val signature = Signature("Dilithium2-AES", privateKeyBytes)
        val privateKey = signature.generate_keypair()

        val dilithium2AESPrivateKey = Dilithium2AESPrivateKey(privateKey)

        println(String(Base64.encode(dilithium2AESPrivateKey.encoded)))
    }

    // Reference test case in:
    // https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/pqc/jcajce/provider/test/Sphincs256Test.java
    @Test
    fun `Dilithium2-AES full process keygen-sign-verify sanity check`() {
        Security.addProvider(OQSProvider)
        val msg = "This is the message to be signed.".toByteArray()

        // keygen
        val kpg = KeyPairGenerator.getInstance("Dilithium2-AES", "OQS")
        val kp = kpg.generateKeyPair()

        // sign
        var sig = java.security.Signature.getInstance("Dilithium2-AES", "OQS")
        sig.initSign(kp.private)
        sig.update(msg, 0, msg.size)
        val s = sig.sign()

        // verify
        sig = java.security.Signature.getInstance("Dilithium2-AES", "OQS")
        sig.initVerify(kp.public)
        sig.update(msg, 0, msg.size)
        assertTrue(sig.verify(s))
    }
}