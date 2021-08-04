package com.mrburny.dilithium

import com.mrburny.OQSProvider
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory
import org.bouncycastle.util.Arrays
import java.io.IOException
import java.security.PrivateKey

/**
 * Implementation of Dilithium private key with BCSphincs256PrivateKey as a reference implementation.
 *
 * PKCS #8 format structure:
 * PrivateKeyInfo ::= SEQUENCE {
 *      version             INTEGER,
 *      privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
 *      privateKey          OCTET STRING,
 *      attributes          IMPLICIT Attributes OPTIONAL
 * }
 * PrivateKeyAlgorithmIdentifier ::= SEQUENCE {
 *      algorithm           OBJECT IDENTIFIER,
 *      parameters          ANY DEFINED BY algorithm OPTIONAL
 * }
 *
 * All OPTIONAL attributes will be omitted for the time being.
 * For the sake of reliability and delivery this feature in time we will use ASN.1-parsing functionality from the bouncy castle.
 */
class Dilithium2AESPrivateKey(
    @Transient
    private val privateKey: ByteArray
) : PrivateKey {

    constructor(privateKeyInfo: PrivateKeyInfo) : this(Arrays.clone(ASN1OctetString.getInstance(privateKeyInfo.parsePrivateKey()).octets))

    override fun getAlgorithm(): String = OQSProvider.DILITHIUM2_AES_ALGORITHM_NAME

    override fun getFormat(): String = "PKCS#8"

    override fun getEncoded(): ByteArray {
        val algorithmIdentifier = AlgorithmIdentifier(ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.11.4.4"))
        return PrivateKeyInfo(algorithmIdentifier, DEROctetString(privateKey)).encoded
    }
}