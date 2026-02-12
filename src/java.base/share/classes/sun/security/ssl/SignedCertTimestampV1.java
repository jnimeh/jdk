/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

package sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.net.ssl.CertTransElement;
import javax.net.ssl.CertTransType;
import javax.net.ssl.SignedCertificateTimestamp;

import sun.security.provider.certpath.CertId;
import sun.security.provider.certpath.OCSPResponse;
import sun.security.util.DerValue;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.ObjectIdentifier;
import static sun.security.x509.PKIXExtensions.*;
import sun.security.x509.SerialNumber;

/**
 * This class defines the signed certificate timestamp (SCT) from RFC 6962.
 * The structure of the SCT is of the form:
 * <pre>
 *  struct {
 *      Version sct_version;
 *      LogID id;
 *      uint64 timestamp;
 *      CtExtensions extensions;
 *      digitally-signed struct {
 *          Version sct_version;
 *          SignatureType signature_type = certificate_timestamp;
 *          uint64 timestamp;
 *          LogEntryType entry_type;
 *          select(entry_type) {
 *              case x509_entry: ASN.1Cert;
 *              case precert_entry: PreCert;
 *          } signed_entry;
 *          CtExtensions extensions;
 *      };
 *  } SignedCertificateTimestamp;
 * </pre>
 */
public abstract class SignedCertTimestampV1 implements
        SignedCertificateTimestamp {
    private static final byte SIG_TYPE_CERT_TIMESTAMP = 0;
    private static final int CTVERSION = 1;

    protected final CertTransType ctType;
    protected final int version;
    protected final byte[] logId;
    protected final Instant timestamp;
    protected final Map<Integer, byte[]> sctExtensions;
    private final SignatureScheme sigScheme;
    protected final byte[] signature;
    protected Signature sigVerifier;
    protected final byte[] encodedSCT;

    /**
     * Construct a SignedCertificateTimestamp (SCT) from the TLS encoded
     * data as a byte array.
     *
     * @param sctData the SerializedSCT structure as a byte array.
     *      This encoding must have the leading length tag stripped.
     *
     * @throws IOException if any parsing errors occur
     */
    protected SignedCertTimestampV1(CertTransType type, byte[] sctData)
            throws IOException {
        this(type, ByteBuffer.wrap(Objects.requireNonNull(sctData,
                "Invalid null SCT data")));
    }

    protected SignedCertTimestampV1(CertTransType type, ByteBuffer sctBuf)
            throws IOException {
        ctType = Objects.requireNonNull(type, "Illegal null CertTransType");
        Objects.requireNonNull(sctBuf, "Illegal null SCT data");
        sctBuf.mark();
        encodedSCT = new byte[sctBuf.remaining()];
        sctBuf.get(encodedSCT);
        sctBuf.reset();
        version = Byte.toUnsignedInt(sctBuf.get());
        if (version != (CTVERSION - 1)) {
            throw new IOException("Detected incorrect version in V1 SCT - " +
                    "expected " + (CTVERSION - 1) + ", received " + version);
        }
        logId = new byte[32];
        sctBuf.get(logId);
        timestamp = Instant.ofEpochMilli(sctBuf.getLong());
        sctExtensions = Utilities.parseTlsExtensions(sctBuf);
        sigScheme = SignatureScheme.valueOf(Record.getInt16(sctBuf));
        signature = Record.getBytes16(sctBuf);
    }

    /**
     * Obtain the type of certificate transparency object.
     *
     * @return a {@code CertTransType} that corresponds to the type
     * of certificate transparency object this is.
     */
    @Override
    public CertTransType getType() {
        return ctType;
    }

    /**
     * Returns the version number of this SCT object.
     *
     * @return the version number of the SCT as an integer
     */
    @Override
    public int getVersion() {
        return version;
    }

    /**
     * Return the log ID for this SCT
     *
     * @return the log identifier
     */
    @Override
    public byte[] getLogId() {
        return logId.clone();
    }

    /**
     * Retrieve the timestamp for this SCT as a Date object.
     *
     * @return the timestamp as a Date object.
     */
    @Override
    public Instant getTimestamp() {
        return timestamp;
    }

    /**
     * Retrieve a copy of the digital signature on the SCT object.
     *
     * @return a copy of the signature data.
     */
    @Override
    public byte[] getSignature() {
        return signature.clone();
    }

    /**
     * Return the extensions for this SCT as an opaque byte array.
     *
     * @return the SCT extension data as a byte array.
     */
    @Override
    public Map<Integer, byte[]> getExtensions() {
        Map<Integer, byte[]> sctExtMap = new LinkedHashMap<>();
        sctExtensions.forEach((id, extData) ->
                sctExtMap.put(id, extData.clone()));
        return sctExtMap;
    }

    /**
     * Verify the digital signature on the SCT.  This form is used when the
     * LogEntryType in the received SCT is precert_entry.
     *
     * @param subjectCert the subject certificate for this SCT.
     * @param issuerKey the subject certificate issuer's public key.
     * @param logKey the log's public key.
     *
     * @return true if the signature matches, false otherwise.
     *
     * @throws SignatureException if an unrecoverable error occurs during
     *      verification.
     */
    @Override
    public boolean verify(X509Certificate subjectCert, PublicKey issuerKey,
                          PublicKey logKey) throws SignatureException  {
        try {
            // Create the signature object the first time it is needed.
            if (sigVerifier == null) {
                sigVerifier = sigScheme.getVerifier(logKey);
            }

            int logEntType = switch (ctType) {
                case X509_SCT -> CertTransType.X509_ENTRY.getId();
                case PRECERT_SCT -> CertTransType.PRECERT_ENTRY.getId();
                default -> throw new SignatureException("Unsupported/Unknown " +
                        "LogEntryType in SCT object: " + ctType);
            };

            try (HandshakeOutStream hos = new HandshakeOutStream(null)) {
                hos.putInt8(version);                       // Version
                hos.putInt8(SIG_TYPE_CERT_TIMESTAMP);       // Sig type
                hos.putInt64(timestamp.toEpochMilli());     // Timestamp
                hos.putInt16(logEntType);                   // Log entry type
                sigVerifier.update(hos.toByteArray());
            }
            // Add signed entry
            sigVerifier.update(getEntryEncoding(subjectCert, issuerKey));
            // Add CtExtensions
            sigVerifier.update(Utilities.encodeTlsExtensions(sctExtensions));

            return sigVerifier.verify(signature);
        } catch (GeneralSecurityException | IOException exc) {
            throw new SignatureException(exc);
        }
    }

    /**
     * Return the signature algorithm used for this SCT as a JCE Signature
     * standard name.
     *
     * @return the String algorithm name for the signature.
     */
    public String getSignatureAlgorithm() {
        return sigScheme.algorithm;
    }

    /**
     * Return the JCE standard name for the key algorithm used to verify
     * the signature on this SCT object.
     *
     * @return the String key algorithm name used to verify the signature.
     */
    public String getLogKeyAlgorithm() {
        return sigScheme.keyAlgorithm;
    }


    /**
     * Retrieve the fully encoded form of the SCT as it was provided to
     * the constructor.  Note that the encoded form is not a SerializedSCT
     * in that it does not have the leading length.  This will allow the
     * resulting byte array to be passed directly into Record.putBytes16().
     *
     * @return a copy of the encoded SCT without the leading 16-bit integer
     *      length.
     */
    @Override
    public byte[] getEncoded() {
        return encodedSCT.clone();
    }

    /**
     * Obtain the encoding for the signed_entry segment of the digitally
     * signed encoding used in SCT verification.
     *
     * @param subjectCert the subject certificate
     * @param issuerKey the issuer certificate's public key
     *
     * @return the encoded ASN.1Cert or PreCert
     *
     * @throws IOException if any non-certificate-based encoding errors occur.
     * @throws GeneralSecurityException if certificate encoding errors
     *          occur or a MessageDigest for key hashing cannot be obtained.
     */
    abstract byte[] getEntryEncoding(X509Certificate subjectCert,
            PublicKey issuerKey) throws IOException,
            GeneralSecurityException;

    /**
     * Equals comparison over the significant fields of an SCT.
     *
     * @param obj the SCT to be compared against.
     *
     * @return true if all significant fields are equal, false otherwise.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        } else if (obj instanceof SignedCertTimestampV1 sct) {
            // Evaluate equality first for all non-collection elements
            boolean areEqual = (this.ctType == sct.ctType &&
                    this.version == sct.version &&
                    Arrays.equals(this.logId, sct.logId) &&
                    this.timestamp.equals(sct.timestamp) &&
                    Arrays.equals(this.signature, sct.signature));
            // Ensure that the elements of the two SCTs extension maps are
            // not only the same, but in the same order.  This matters as it
            // impacts the signature.
            areEqual &= (this.sctExtensions.size() == sct.sctExtensions.size());
            var thisIt = sctExtensions.entrySet().iterator();
            var sctIt = sct.sctExtensions.entrySet().iterator();
            while (thisIt.hasNext() && areEqual) {
                var thisEnt = thisIt.next();
                var sctEnt = sctIt.next();
                areEqual = (thisEnt.getKey().equals(sctEnt.getKey()) &&
                        Arrays.equals(thisEnt.getValue(), sctEnt.getValue()));
            }
            return areEqual;
        } else {
            return false;
        }
    }

    /**
     * Hashcode implementation to support equality comparisons and inclusion
     * in hash-based collections.
     *
     * @return the hash code value for this object.
     */
    @Override
    public int hashCode() {
        int result = ctType.hashCode();
        result = (31 * result) + Integer.hashCode(version);
        result = (31 * result) + Arrays.hashCode(logId);
        result = (31 * result) + timestamp.hashCode();
        for (Map.Entry<Integer, byte[]> ent : sctExtensions.entrySet()) {
            result = (31 * result) + Integer.hashCode(ent.getKey());
            result = (31 * result) + Arrays.hashCode(ent.getValue());
        }
        result = (31 * result) + Arrays.hashCode(signature);
        return result;
    }

    /**
     * Print out the signed certificate timestamp as a String object.
     *
     * @return the String representation of this SCT object.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append("Signed Certificate Timestamp:");
        sb.append("\nVersion: ").append(version);
        sb.append("\nLog ID: ").append(Utilities.toHexString(logId));
        sb.append("\nTimestamp: ").append(DateTimeFormatter.RFC_1123_DATE_TIME.
                format(timestamp.atOffset(ZoneOffset.UTC)));
        sb.append("\nCT Extensions: { ");
        if (sctExtensions.isEmpty()) {
            sb.append("}");
        } else {
            sctExtensions.forEach((extId, extData) -> sb.append(
                    String.format("\n    Extension: (0x%04X), %d bytes",
                            extId, extData.length)));
            sb.append("\n}");
        }
        sb.append("\nSignature (not shown, ").append(signature.length).
                append(" bytes)");

        return sb.toString();
    }

    /**
     * Obtain a List of SCT objects from a serialized
     * SignedCertificateTimestampList structure as specified in RFC 6962.
     * The list is defined as follows:
     * <pre>
     * opaque SerializedSCT<1..2^16-1>;
     *
     * struct {
     *     SerializedSCT sct_list<1..2^16-1>;
     * } SignedCertificateTimestampList;
     * </pre>
     *
     * @param sctType the kind of SCT being parsed (must be either
     *                {@code CertTransType.X509_SCT} or
     *                {@code CertTransType.PRECERT_SCT}
     * @param encoded the serialized form of the SignedCertificateTimestampList
     *                as a ByteBuffer.  The buffer should be positioned at the
     *                leading length for the sct_list.
     *
     * @return a {@code Set} containing the SCTs as {@code CertTransElement}
     * objects.
     *
     * @throws IOException if the SignedCertificateTimestampList is empty,
     *         or any parsing errors occur.
     * @throws IllegalArgumentException if the {@code sctType} parameter is
     *         a value other than X509_SCT or PRECERT_SCT.
     */
    public static Set<CertTransElement> getSCTs(CertTransType sctType,
            ByteBuffer encoded) throws IOException {
        if (sctType != CertTransType.X509_SCT && sctType !=
                CertTransType.PRECERT_SCT) {
            throw new IllegalArgumentException("Incorrect CertTransType: " +
                    sctType);
        }

        // Check overall length
        int sctListLen = Record.getInt16(encoded);
        if (sctListLen <= 0) {
            throw new IOException("Illegal SCT list length: " + sctListLen);
        } else if (sctListLen != encoded.limit() - 2) {
            throw new IOException("SCT List length mismatch, expected " +
                    sctListLen + ", got " + (encoded.limit() - 2));
        }

        // Parse each SerializedSCT structure
        try {
            Set<CertTransElement> sctList = new LinkedHashSet<>();
            while (encoded.hasRemaining()) {
                // Slice the serialized SCT list byte buffer to contain a
                // single encoded SCT after reading the vector length.
                int singleSctLen = Record.getInt16(encoded);
                ByteBuffer singleSct = encoded.slice(encoded.position(),
                        singleSctLen);
                sctList.add(sctType == CertTransType.PRECERT_SCT ?
                        new PreCertSctV1(singleSct) :
                        new X509CertSctV1(singleSct));
                encoded.position(encoded.position() + singleSctLen);
            }
            return sctList;
        } catch (GeneralSecurityException gse) {
            throw new IOException(gse);
        }
    }

    /**
     * From an input X509Certificate object, obtain Signed Certificate
     * Timestamps and return them in a Set.
     *
     * @param cert the X509Certificate object to be parsed
     *
     * @return a {@code Set} of signed certificate timestamps found in the
     *         signedCertificateTimestampList certificate extension.  If the
     *         extension is not present, an empty {@code Set} will be returned.
     *
     * @throws IOException if any parsing errors occur.
     */
    static Set<CertTransElement> getSCTListFromCert(X509Certificate cert)
            throws IOException {
        Set<CertTransElement> certSctSet = Collections.emptySet();
        if (cert != null) {
            byte[] extDataDer = cert.getExtensionValue(
                    SignedCertificateTimestampList_Id.toString());
            if (extDataDer != null) {
                DerValue encapsOctStr = new DerValue(extDataDer);
                DerValue innerOctStr =
                        new DerValue(encapsOctStr.getOctetString());
                certSctSet = getSCTs(CertTransType.PRECERT_SCT,
                        ByteBuffer.wrap(innerOctStr.getOctetString()));
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.fine("Found " + certSctSet.size() +
                            " unique SCT entries from X.509 Certificate");
                }
            }
        }
        return certSctSet;
    }

    static Set<CertTransElement> getSCTListFromOCSP(X509Certificate subject,
            X509Certificate issuer, byte[] ocspResponseData)
            throws IOException {
        Set<CertTransElement> ocspSctSet = Collections.emptySet();

        if (ocspResponseData != null && ocspResponseData.length > 0) {
            OCSPResponse oResp = new OCSPResponse(ocspResponseData);
            CertId cid = new CertId(issuer,
                    new SerialNumber(subject.getSerialNumber()));
            OCSPResponse.SingleResponse sr = oResp.getSingleResponse(cid);
            if (sr != null) {
                Extension sctExt = sr.getSingleExtensions().get(
                        SignedCertificateTimestampListOCSP_Id.toString());
                if (sctExt != null) {
                    // Strip off the leading OCTET STRING encapsulation
                    DerInputStream dis = new DerInputStream(sctExt.getValue());
                    ocspSctSet = getSCTs(CertTransType.X509_SCT,
                            ByteBuffer.wrap(dis.getOctetString()));
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("Found " + ocspSctSet.size() +
                                " unique SCT entries from OCSP response");
                    }
                }
            }
        }
        return ocspSctSet;
    }

//    static void addSCTListFromOCSP(ClientHandshakeContext chc)
//            throws IOException {
//        X509Certificate[] certs = (X509Certificate[])
//                chc.handshakeSession.getPeerCertificates();
//        List<byte[]> oResps = chc.handshakeSession.getStatusResponses();
//
//        // We will need at least the server certificate and its issuer to
//        // Create a CertID so we only scoop up responses for that cert.
//        // If we don't have them then log it and bail out.
//        if (certs.length < 2) {
//            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//                SSLLogger.fine("Warning: unable to build CertId from peer " +
//                        "certificate list, no issuer found");
//            }
//            return;
//        }
//
//        if (!oResps.isEmpty()) {
//            byte[] oRespData = oResps.getFirst();
//            if (oRespData.length > 0) {
//                OCSPResponse oResp = new OCSPResponse(oRespData);
//                CertId cid = new CertId(certs[1],
//                        new SerialNumber(certs[0].getSerialNumber()));
//                OCSPResponse.SingleResponse sr = oResp.getSingleResponse(cid);
//                if (sr != null) {
//                    Extension sctExt = sr.getSingleExtensions().get(
//                            SignedCertificateTimestampListOCSP_Id.toString());
//                    if (sctExt != null) {
//                        // Strip off the leading OCTET STRING encapsulation
//                        DerInputStream dis = new DerInputStream(
//                                sctExt.getValue());
//                        //TODO
//                        List<X509CertSctV1> extSctList =
//                                SignedCertificateTimestamp.getSCTList(
//                                        X509CertSctV1.class,
//                                        dis.getOctetString());
//                        chc.sctCache.addSct(certs[0], extSctList);
//                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//                            SSLLogger.fine("Added " + extSctList.size() +
//                                    " entries to handshake SCT List");
//                        }
//                    }
//                }
//            }
//        }
//    }

    public static final class PreCertSctV1 extends SignedCertTimestampV1 {

        public PreCertSctV1(ByteBuffer data) throws IOException,
                NoSuchAlgorithmException {
            super(CertTransType.PRECERT_SCT, data);
        }

        @Override
        byte[] getEntryEncoding(X509Certificate subjectCert,
                PublicKey issuerKey) throws IOException,
                GeneralSecurityException {
            try (HandshakeOutStream hos = new HandshakeOutStream(null)) {
                MessageDigest hash = MessageDigest.getInstance("SHA-256");
                // Get the issuer key hash
                hos.write(hash.digest(issuerKey.getEncoded()));

                // Get the TBSCert data, add it to the encoding, but remove
                // the signed_certificate_timestamp extension
                hos.putBytes24(getPreCert(subjectCert.getTBSCertificate()));
                return hos.toByteArray();
            }
        }

        private byte[] getPreCert(byte[] tbsCertDer) throws IOException {
            DerOutputStream tbsCertOutStream =
                    new DerOutputStream(tbsCertDer.length);
            DerOutputStream tbsItems = new DerOutputStream(tbsCertDer.length);
            DerInputStream dis = new DerInputStream(tbsCertDer);

            DerValue[] dvOutSeq = dis.getSequence(10);
            for (DerValue dv : dvOutSeq) {
                if (dv.isContextSpecific((byte)3) && dv.isConstructed()) {
                    DerOutputStream modExts = filterExtensions(dv,
                            List.of(SignedCertificateTimestampList_Id));
                    tbsItems.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                            true, (byte)3), modExts);
                } else {
                    tbsItems.putDerValue(dv);
                }
            }

            tbsCertOutStream.write(DerValue.tag_Sequence, tbsItems);
            return tbsCertOutStream.toByteArray();
        }

        private DerOutputStream filterExtensions(DerValue a3dv,
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
    }

    public static final class X509CertSctV1 extends SignedCertTimestampV1 {

        public X509CertSctV1(ByteBuffer data) throws IOException {
            super(CertTransType.X509_SCT, data);
        }

        @Override
        byte[] getEntryEncoding(X509Certificate subjectCert,
                PublicKey issuerKey) throws IOException,
                CertificateEncodingException {
            try (HandshakeOutStream hos = new HandshakeOutStream(null)) {
                hos.putBytes24(subjectCert.getEncoded());
                return hos.toByteArray();
            }
        }
    }
}
