package com.mrburny.dilithium

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class Dilithium2AESPublicKeyTest {
    private val validZeros = ByteArray(1312)
    private val invalidZeros = ByteArray(1313)

    private val subject = Dilithium2AESPublicKey(validZeros)

    @Test
    fun `should return defined algorithm identifier`() {
        assertEquals("Dilithium2-AES", subject.algorithm)
    }

    @Test
    fun `should return defined format`() {
        assertEquals("X.509", subject.format)
    }

    @Test
    fun `should throw exception on byte array of invalid size in constructor`() {
        assertThrows<IllegalStateException> { Dilithium2AESPublicKey(invalidZeros) }
    }

    @Test
    fun `should encode public key wrt RFC 5280`() {
        val objectDescriptorBytes = arrayOf<Byte>(48, -126, 5, 52).toByteArray()
        val algorithmIdentifierBytes = AlgorithmIdentifier(ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.11.4.4")).encoded
        val zerosBitString = DERBitString(validZeros).encoded
        val concatenatedBytes = objectDescriptorBytes + algorithmIdentifierBytes + zerosBitString
        val encodedPublicKey = subject.encoded

        assertTrue(concatenatedBytes.contentEquals(encodedPublicKey), "Encoded public key doesn't match expected")
    }
}
