package com.mrburny.dilithium

import com.mrburny.OQSProvider.DILITHIUM2_AES_ALGORITHM_NAME
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SignatureSpi
import org.openquantumsafe.Signature

@Suppress("unused")
class Dilithium2AESSignature : SignatureSpi() {

    companion object {
        const val DEFAULT_MESSAGE_SIZE = 1024
    }

    private var publicKey: PublicKey? = null
    private var privateKey: PrivateKey? = null

    private var data: ByteArray = ByteArray(DEFAULT_MESSAGE_SIZE)
    private var offset = 0

    //TODO: do research on its purpose
    private val parameters: MutableMap<String?, Any?> = mutableMapOf()

    override fun engineInitVerify(publicKey: PublicKey?) {
        this.publicKey = publicKey
        this.data = ByteArray(DEFAULT_MESSAGE_SIZE)
    }

    override fun engineInitSign(privateKey: PrivateKey?) {
        this.privateKey = privateKey
        this.data = ByteArray(DEFAULT_MESSAGE_SIZE)
    }

    override fun engineUpdate(b: Byte) {
        data[offset] = b
        offset++

        if (offset == data.size) {
            expandArray()
        }
    }

    private fun expandArray() {
        val extended = ByteArray(data.size * 2)
        data.copyInto(extended)
        data = extended
    }

    override fun engineUpdate(b: ByteArray?, off: Int, len: Int) {
        if (b == null) {
            return
        }

        val exclusiveEnd = off + len
        var updateOffset = off
        while (updateOffset < exclusiveEnd) {
            engineUpdate(b[updateOffset])
            updateOffset++
        }
    }

    override fun engineSign(): ByteArray {
        if (privateKey == null) {
            throw Exception("Pass private key before signing")
        }
        val signature = Signature(DILITHIUM2_AES_ALGORITHM_NAME, privateKey!!.encoded)
        return signature.sign(data)
    }

    override fun engineVerify(sigBytes: ByteArray?): Boolean {
        val signature = Signature(DILITHIUM2_AES_ALGORITHM_NAME, privateKey!!.encoded)
        return signature.verify(data, sigBytes, publicKey!!.encoded)
    }

    override fun engineSetParameter(param: String?, value: Any?) {
        parameters[param] = value
    }

    override fun engineGetParameter(param: String?): Any? {
        return parameters[param]
    }
}