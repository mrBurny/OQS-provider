package com.mrburny.dilithium

import com.mrburny.OQSProvider.DILITHIUM2_AES_ALGORITHM_NAME
import org.openquantumsafe.Signature
import java.security.KeyPair
import java.security.KeyPairGeneratorSpi
import java.security.SecureRandom

@Suppress("unused")
class Dilithium2AESKeyPairGeneratorSpi : KeyPairGeneratorSpi() {

    private var privateKeyBytes: ByteArray? = null

    override fun initialize(keysize: Int, random: SecureRandom?) {
        privateKeyBytes = ByteArray(keysize)
        random?.nextBytes(privateKeyBytes)
    }

    override fun generateKeyPair(): KeyPair {
        val signature = Signature(DILITHIUM2_AES_ALGORITHM_NAME, privateKeyBytes)
        val publicKeyBytes = signature.generate_keypair()
        val publicKey = Dilithium2AESPublicKey.withValue(publicKeyBytes)

        val privateKeyBytes = signature.export_secret_key()
        val privateKey = Dilithium2AESPrivateKey(privateKeyBytes)

        return KeyPair(publicKey, privateKey)
    }
}