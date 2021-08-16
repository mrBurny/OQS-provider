package com.mrburny.dilithium

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class Dilithium2AESPrivateKeyTest {
    private val validZeros = ByteArray(2528)
    private val invalidZeros = ByteArray(2529)

    private val subject = Dilithium2AESPrivateKey(validZeros)

    @Test
    fun `should return defined algorithm identifier`() {
        Assertions.assertEquals("Dilithium2-AES", subject.algorithm)
    }

    @Test
    fun `should return defined format`() {
        Assertions.assertEquals("PKCS#8", subject.format)
    }

    @Test
    fun `should throw exception on byte array of invalid size in constructor`() {
        assertThrows<IllegalStateException> { Dilithium2AESPrivateKey(invalidZeros) }
    }

    @Test
    fun `should encode private key wrt RFC 5208`() {
        val objectDescriptorBytes = arrayOf<Byte>(48, -126, 9, -6, 2, 1, 0).toByteArray()
        val algorithmIdentifierBytes = AlgorithmIdentifier(ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.11.4.4")).encoded
        val privateKeyDescriptorBytes = arrayOf<Byte>(4, -126, 9, -28).toByteArray()
        val zerosOctetStringString = DEROctetString(validZeros).encoded
        val concatenatedBytes = objectDescriptorBytes + algorithmIdentifierBytes + privateKeyDescriptorBytes + zerosOctetStringString
        val encodedPrivateKey = subject.encoded

        Assertions.assertTrue(
            concatenatedBytes.contentEquals(encodedPrivateKey),
            "Encoded private key doesn't match expected"
        )
    }
}