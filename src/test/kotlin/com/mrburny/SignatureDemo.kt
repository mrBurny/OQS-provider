package com.mrburny

import com.mrburny.dilithium.Dilithium2AESPrivateKey
import org.bouncycastle.util.encoders.Base64
import org.junit.jupiter.api.Test
import org.openquantumsafe.Signature
import java.security.SecureRandom

class SignatureDemo {

    @Test
    fun `should generate signature`() {
        val random = SecureRandom()
        val privateKeyBytes = ByteArray(2528)
        random.nextBytes(privateKeyBytes)

        val signature = Signature("Dilithium2-AES", privateKeyBytes)
        val privateKey = signature.generate_keypair()

        println(signature.export_public_key().size)

        val dilithium2AESPrivateKey = Dilithium2AESPrivateKey(privateKey)

        println(String(Base64.encode(dilithium2AESPrivateKey.encoded)))
    }
}