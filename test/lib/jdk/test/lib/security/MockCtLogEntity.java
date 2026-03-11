/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package jdk.test.lib.security;

import sun.security.ssl.SignedCertTimestampV1;
import sun.security.util.*;

import javax.net.ssl.SignedCertificateTimestamp;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import static sun.security.x509.PKIXExtensions.*;

public class MockCtLogEntity {

    private record SctSignerInfo(String jceSignAlg, int tlsSigSchemeId) { }

    private static final int VERSION = 0;           // v1
    private static final int CT_SIG_TYPE = 0;       // certificate_timestamp(0)
    private static final int TYPE_X509SCT = 0;      // x509_entry(0)
    private static final int TYPE_PRECERTSCT = 1;   // precert_entry(1)

    private final byte[] logId;
    private final KeyPair keys;
    private final SctSignerInfo sigInfo;

    private static final SecureRandom RAND = new SecureRandom();

    public MockCtLogEntity() throws GeneralSecurityException, IOException {
        this("EC:secp256r1");
    }

    public MockCtLogEntity(byte[] id, KeyPair signingKp)
            throws GeneralSecurityException, IOException {
        logId = Objects.requireNonNull(id, "Illegal null log ID");
        keys = Objects.requireNonNull(signingKp, "Illegal null key pair");
        sigInfo = getSignerInfo(keys);
    }

    public MockCtLogEntity(String keyspec)
            throws GeneralSecurityException, IOException {
        // Generate a random logID
        logId = new byte[32];
        RAND.nextBytes(logId);
        keys = getKpg(keyspec).generateKeyPair();
        sigInfo = getSignerInfo(keys);
    }

    public byte[] getLogId() {
        return logId.clone();
    }

    public PublicKey getLogPubkey() {
        return keys.getPublic();
    }

    public SignedCertificateTimestamp getX509Sct(X509Certificate cert)
            throws IOException, GeneralSecurityException {
        // Set the signing time (whatever time it is right now)
        Instant sctTimestamp = Instant.now();
        return createSct(TYPE_X509SCT, sctTimestamp, cert.getEncoded());
    }

    public SignedCertificateTimestamp getPreCertSct(PublicKey certIssuerKey,
            byte[] tbsCertDer) throws IOException {
        // First, prep the pre-cert in order to make the signed_entry
        try (var baos = new ByteArrayOutputStream()) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            baos.write(md.digest(certIssuerKey.getEncoded()));

            // Create the tbs_certificate portion of the pre-cert.  Since
            // we don't know whether we're getting a Pre-certificate with a
            // poison extension or we're reconstructing it from a final issued
            // cert we'll look for and remove any poison or SCT extension.
            DerOutputStream tbsCertOutStream =
                    new DerOutputStream(tbsCertDer.length);
            DerOutputStream tbsItems = new DerOutputStream(tbsCertDer.length);
            DerInputStream dis = new DerInputStream(tbsCertDer);

            // Go through the top-level TBSCertificate objects looking for
            // the extensions section.
            DerValue[] dvOutSeq = dis.getSequence(10);
            for (DerValue dv : dvOutSeq) {
                if (dv.isContextSpecific((byte) 3) && dv.isConstructed()) {
                    // Get a DerOutputStream that contains the extensions
                    // in the same order, but without certain extensions that
                    // must be filtered before creating an SCT.
                    DerOutputStream modExts = filterExtensions(dv,
                            List.of(SignedCertificateTimestampList_Id,
                                    CertificateTransparencyPoison_Id));
                    tbsItems.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                            true, (byte) 3), modExts);
                } else {
                    tbsItems.putDerValue(dv);
                }
            }

            tbsCertOutStream.write(DerValue.tag_Sequence, tbsItems);
            baos.write(tbsCertOutStream.toByteArray());

            Instant sctTimestamp = Instant.now();
            return createSct(TYPE_PRECERTSCT, sctTimestamp, baos.toByteArray());
        } catch (GeneralSecurityException gse) {
            throw new IOException("Failed to create public key hash", gse);
        }
    }

    private static DerOutputStream filterExtensions(DerValue a3dv,
            List<ObjectIdentifier> oidsToFilter) throws IOException {
        DerOutputStream extsOuterSeq = new DerOutputStream(a3dv.length());
        DerOutputStream extsItems = new DerOutputStream(a3dv.length());
        DerInputStream extsDis = a3dv.getData();

        DerValue[] extArray = extsDis.getSequence(10);
        for (DerValue dv : extArray) {
            // Individual extension
            DerInputStream singleExtDis = dv.getData();
            ObjectIdentifier extOid = singleExtDis.getOID();
            if (!oidsToFilter.contains(extOid)) {
                extsItems.putDerValue(dv);
            }
        }

        // Write the outer SEQUENCE tag for the Extensions
        extsOuterSeq.write(DerValue.tag_Sequence, extsItems);
        return extsOuterSeq;
    }

    private SignedCertificateTimestamp createSct(int type, Instant sigTime,
            byte[] sigEntData) throws IOException, GeneralSecurityException {
        try (var baos = new ByteArrayOutputStream();
             var dos = new DataOutputStream(baos)) {
            dos.writeByte(VERSION);
            dos.write(logId);
            dos.writeLong(sigTime.toEpochMilli());
            dos.writeShort(0);                  // Empty CtExtensions
            dos.write(makeDigitalSignature(type, sigTime, sigEntData));

            return switch (type) {
                case TYPE_X509SCT -> new SignedCertTimestampV1.X509CertSctV1(
                        ByteBuffer.wrap(baos.toByteArray()));
                case TYPE_PRECERTSCT -> new SignedCertTimestampV1.PreCertSctV1(
                        ByteBuffer.wrap(baos.toByteArray()));
                default -> throw new IllegalArgumentException(
                        "Unknown LogEntryType: " + type);   // Should not happen
            };
        }
    }

    /**
     * Create the {@code digitally-signed} TLS signed structure as defined in
     * RFC 5246:
     * <pre>
     * struct {
     *      SignatureAndHashAlgorithm algorithm;
     *      opaque signature<0..2^16-1>;
     * } DigitallySigned;
     * </pre>
     *
     * @param type the LogEntryType for this signature
     * @param sigTime the signing time
     * @param signedEntry the signed entry itself (pre-cert vs. ASN.1 cert)
     *
     * @return a byte array containing the serialized DigitallySigned structure
     * @throws IOException if errors occur when parsing keys for parameters
     *         or problems with JCE instantiation occur.
     * @throws GeneralSecurityException if there are issues instantiating the
     *         {@code Signature} object or an invalid key pair is provided.
     */
    private byte[] makeDigitalSignature(int type, Instant sigTime,
            byte[] signedEntry) throws IOException, GeneralSecurityException {
        try (var baos = new ByteArrayOutputStream();
             var dos = new DataOutputStream(baos)) {
            Signature signer = Signature.getInstance(sigInfo.jceSignAlg);
            signer.initSign(keys.getPrivate());

            // Start building the digitally-signed struct
            dos.writeByte(VERSION);
            dos.writeByte(CT_SIG_TYPE);
            dos.writeLong(sigTime.toEpochMilli());
            dos.writeShort(type);
            dos.write(signedEntry);
            dos.writeShort(0);                  // Empty CtExtensions
            signer.update(baos.toByteArray());

            // Write the outer DigitallySigned structure (alg id and sig)
            try (var dsBaos = new ByteArrayOutputStream();
                 var dsDos = new DataOutputStream(dsBaos)) {
                dsDos.writeShort(sigInfo.tlsSigSchemeId);
                dsDos.write(signer.sign());
                return dsBaos.toByteArray();
            }
        }
    }

    public String toString() {
        HexFormat hex = HexFormat.of().withUpperCase();
        return "Mock CT Log:\nID: " + hex.formatHex(logId) +
                "\nKeys: " + keys.getPublic();
    }

    /**
     * Return an initialize {@code KeyPairGenerator} from a key specification.
     * The specification takes the form of [ALG]:[PARAM]. Where alg can be
     * any signature-capable type from the Java Standard Algorithm names table
     * for KeyPairGenerator (except for DSA).  PARAM is only needed when
     * ALG doesn't imply the parameters and a missing value will have a default
     * assigned for it:
     * <LI>EdDSA: takes a string value {@code Ed25519} or {@code Ed448}.
     *         Defaults to {@code Ed25519}.
     * <LI>ML-DSA: takes {@code ML-DSA-44}, {@code ML-DSA-65} or
     *         {@code ML-DSA-87}
     * <LI>EC: takes a curve name (e.g. {@code secp521r1}).  Defaults to
     *         {@code secp256r1}.
     * <LI>RSA: takes a modulus bit length, defaults to 2048.
     *
     * @param keyspec the key specification as described above.
     *
     * @return an initialized {@code KeyPairGenerator} suitable for making keys.
     *
     * @throws GeneralSecurityException if there are problems with the key
     *         specifier that would prevent instantiation/initialization of
     *         a {@code KeyPairGenerator}.
     */
    private static KeyPairGenerator getKpg(String keyspec)
            throws GeneralSecurityException {
        String[] kpgComps = (keyspec != null ? keyspec : "EC:secp256r1").
                split(":", 2);
        // Technically only RSA-2048 (or larger) and EC:secp256r1 are allowed
        // per RFC 6962 2.1.4, but we'll allow greater latitude here for testing
        // purposes.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(kpgComps[0]);
        // Add params (where needed)
        switch (kpgComps[0].toUpperCase()) {
            case "ED25519", "ED448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" -> {
                // Do nothing, we allow these types (params implied)
            }
            case "EDDSA" -> {
                NamedParameterSpec curve = (kpgComps.length < 2 ||
                        kpgComps[1] == null) ? NamedParameterSpec.ED25519 :
                        new NamedParameterSpec(kpgComps[1]);
                kpg.initialize(curve, RAND);
            }
            case "ML-DSA" -> {
                NamedParameterSpec params = (kpgComps.length < 2 ||
                        kpgComps[1] == null) ? NamedParameterSpec.ML_DSA_44 :
                        new NamedParameterSpec(kpgComps[1]);
                kpg.initialize(params, RAND);
            }
            case "EC" -> {
                ECGenParameterSpec curve = (kpgComps.length < 2 ||
                        kpgComps[1] == null) ?
                        new ECGenParameterSpec("secp256r1") :
                        new ECGenParameterSpec(kpgComps[1]);
                kpg.initialize(curve, RAND);
            }
            case "RSA" -> {
                int keySize = (kpgComps.length < 2 || kpgComps[1] == null) ?
                        2048 : Integer.parseInt(kpgComps[1]);
                kpg.initialize(new RSAKeyGenParameterSpec(keySize,
                        RSAKeyGenParameterSpec.F4));
            }
            default -> throw new IllegalArgumentException("\"" + kpgComps[0] +
                    "\" is disallowed or invalid");
        }
        return kpg;
    }

    /**
     * Provide the 16-bit numeric SignatureScheme ID given a KeyPair for SCT
     * signing.  Per RFC 6962, this should only be RSA (>= 2048 bit) or P-256
     * EC keys, but this method will allow other types of signing keys in order
     * to allow negative testing with other signing algorithms.
     *
     * @param keys a {@code KeyPair} containing signing keys for the SCT
     *
     * @return the unsigned 16-bit SignatureScheme ID value
     *
     * @throws IOException if issues while parsing key data occur
     * @throws InvalidKeyException if a {@code KeyPair} containing keys not
     *         suitable for digital signature (e.g. X25519) is provided.
     */
    private static SctSignerInfo getSignerInfo(KeyPair keys)
            throws IOException, InvalidKeyException {
        String keyType = keys.getPublic().getAlgorithm().toUpperCase();
        return switch (keyType) {
            case "RSA" -> new SctSignerInfo("SHA256withRSA", 0x0401);
            case "EC" -> {
                KnownOIDs curveOid = getEcCurveByPubkey(keys.getPublic());
                yield switch (curveOid) {
                    case KnownOIDs.secp256r1 ->
                            new SctSignerInfo("SHA256withECDSA", 0x0403);
                    case KnownOIDs.secp384r1 ->
                            new SctSignerInfo("SHA384withECDSA", 0x0503);
                    case KnownOIDs.secp521r1 ->
                            new SctSignerInfo("SHA512withECDSA", 0x0603);
                    default -> throw new InvalidKeyException(
                            "Unsupported named curve: " + curveOid);
                };
            }
            case "ED25519" -> new SctSignerInfo("Ed25519", 0x0807);
            case "ED448" -> new SctSignerInfo("Ed448", 0x0808);
            case "ML-DSA-44" -> new SctSignerInfo("ML-DSA-44", 0x0904);
            case "ML-DSA-65" -> new SctSignerInfo("ML-DSA-65", 0x0905);
            case "ML-DSA-87" -> new SctSignerInfo("ML-DSA-87", 0x0906);
            case "ML-DSA", "EDDSA" -> {
                String paramName =
                        ((NamedParameterSpec)keys.getPublic().getParams()).
                                getName().toUpperCase();
                yield switch (paramName) {
                    case "ED25519" -> new SctSignerInfo("Ed25519", 0x0807);
                    case "ED448" -> new SctSignerInfo("Ed448", 0x0808);
                    case "ML-DSA-44" -> new SctSignerInfo("ML-DSA-44", 0x0904);
                    case "ML-DSA-65" -> new SctSignerInfo("ML-DSA-65", 0x0905);
                    case "ML-DSA-87" -> new SctSignerInfo("ML-DSA-87", 0x0906);
                    default -> throw new InvalidKeyException(
                            "Unsupported NamedParameterSpec: " + paramName);
                };
            }
            default -> throw new InvalidKeyException("Unsupported key type: " +
                    keyType);
        };
    }

    private static KnownOIDs getEcCurveByPubkey(PublicKey pubKey)
            throws IOException {
        if (pubKey instanceof ECPublicKey ecKey) {
            DerInputStream dis = new DerInputStream(ecKey.getEncoded());
            DerValue[] topItems = dis.getSequence(2);   // AlgID and key bitstring
            for (DerValue it : topItems) {
                System.out.println("DV type: " + it.tag);
            }
            DerValue[] algIdItems = topItems[0].data().getSequence(2);
            // The first item must be an OID of type id-ecPublicKey
            // (1.2.840.10045.2.1).  The parameters field can take a few different
            // forms, but we're only going to support the named curve format (an
            // OID).  Any other non-OID parameter type will throw IOException.
            if (algIdItems.length == 2) {
                ObjectIdentifier keyAlgOid =
                        Objects.requireNonNull(algIdItems[0]).getOID();
                if (KnownOIDs.findMatch(keyAlgOid.toString()) == KnownOIDs.EC) {
                    ObjectIdentifier curveOid =
                            Objects.requireNonNull(algIdItems[1]).getOID();
                    return KnownOIDs.findMatch(curveOid.toString());
                } else {
                    throw new IOException("Unexpected key algorithm OID: " +
                            keyAlgOid);
                }
            } else {
                throw new IOException("Incorrect number of items in" +
                        "AlgorithmIdentifier: expected 2, received " +
                        algIdItems.length);
            }
        } else {
            throw new IOException("Expected ECPublicKey, got " +
                    pubKey.getClass().getName());
        }
    }
}
