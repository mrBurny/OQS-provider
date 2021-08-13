package com.mrburny.dilithium

import com.mrburny.OQSProvider.DILITHIUM2_AES_ALGORITHM_NAME
import org.openquantumsafe.Signature
import java.io.ByteArrayOutputStream
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SignatureSpi

@Suppress("unused")
class Dilithium2AESSignatureSpi : SignatureSpi() {

    private var publicKey: Dilithium2AESPublicKey? = null
    private var privateKey: Dilithium2AESPrivateKey? = null

    private var data = ByteArrayOutputStream()
    private var offset = 0

    // TODO: do research on its purpose
    private val parameters: MutableMap<String?, Any?> = mutableMapOf()

    override fun engineInitVerify(publicKey: PublicKey?) {
        if (publicKey !is Dilithium2AESPublicKey) {
            throw IllegalArgumentException("Public key must be an instance of Dilithium2AESPublicKey")
        }

        this.publicKey = publicKey
        this.data = ByteArrayOutputStream()
    }

    override fun engineInitSign(privateKey: PrivateKey?) {
        if (privateKey !is Dilithium2AESPrivateKey) {
            throw IllegalArgumentException("Public key must be an instance of Dilithium2AESPrivateKey")
        }

        this.privateKey = privateKey
        this.data = ByteArrayOutputStream()
    }

    override fun engineUpdate(b: Byte) = this.data.write(b.toInt())

    override fun engineUpdate(b: ByteArray?, off: Int, len: Int) {
        if (b == null) {
            return
        }

        data.write(b, off, len)
    }

    override fun engineSign(): ByteArray {
        if (privateKey == null) {
            throw Exception("Pass private key before signing")
        }
        val signature = Signature(DILITHIUM2_AES_ALGORITHM_NAME, privateKey!!.getKeyContent())
        return signature.sign(data.toByteArray())
    }

    override fun engineVerify(sigBytes: ByteArray?): Boolean {
        // We're not supposed to know the private key before we verify!
        val signature = Signature(DILITHIUM2_AES_ALGORITHM_NAME)
        return signature.verify(data.toByteArray(), sigBytes, publicKey!!.getKeyContent())
    }

    override fun engineSetParameter(param: String?, value: Any?) {
        parameters[param] = value
    }

    override fun engineGetParameter(param: String?): Any? {
        return parameters[param]
    }
}