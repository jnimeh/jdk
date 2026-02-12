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
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.Signature;
import java.security.cert.*;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.text.SimpleDateFormat;

import sun.security.provider.certpath.CertId;
import sun.security.provider.certpath.OCSPResponse;
import sun.security.util.DerValue;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.HexDumpEncoder;
import sun.security.util.KnownOIDs;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.PKIXExtensions;
import static sun.security.x509.PKIXExtensions.*;
import sun.security.x509.SerialNumber;
import sun.security.x509.X509CRLImpl;
import sun.security.x509.X509CertInfo;

import javax.net.ssl.CertTransElement;
import javax.net.ssl.CertTransType;
import javax.net.ssl.SSLException;
import javax.net.ssl.SignedCertificateTimestamp;

/**
 * Implementation of the TransItem CT structure.
 * The TransItem structure is as follows:
 * <pre>
 * struct {
 *      VersionedTransType versioned_type;
 *      select (versioned_type) {
 *          case x509_entry_v2: TimestampedCertificateEntryDataV2;
 *          case precert_entry_v2: TimestampedCertificateEntryDataV2;
 *          case x509_sct_v2: SignedCertificateTimestampDataV2;
 *          case precert_sct_v2: SignedCertificateTimestampDataV2;
 *          case signed_tree_head_v2: SignedTreeHeadDataV2;
 *          case consistency_proof_v2: ConsistencyProofDataV2;
 *          case inclusion_proof_v2: InclusionProofDataV2;
 *      } data;
 * } TransItem;
 * </pre>
 */
public abstract class TransItem implements CertTransElement {
    public static final int CTVERSION = 2;

    protected final CertTransType ctType;
    protected byte[] encodedData;

    /**
     * Protected constructor for a {@code TransItem} object
     *
     * @param type the {@code CertTransType} corresponding to this
     *        {@code TransItem}.  This may be null in the case of experimental
     *        or private types.
     *
     */
    protected TransItem(CertTransType type) {
        ctType = type;
    }

    @Override
    public CertTransType getType() {
        return ctType;
    }

    @Override
    public int getVersion() {
        return CTVERSION;
    }

    protected void copyEncodedBytes(int start, ByteBuffer data) {
        data.position(start);
        encodedData = new byte[data.remaining()];
        data.get(encodedData);
    }

    @Override
    public String toString() {
        return "TransItem: " + (ctType != null ? ctType : "unknown");
    }

    private static CertTransType versTransTypeToCTT(int vttId) {
        // For this conversion, we expect the type to be v2(0x01) so
        // any other leading version byte will result in a null CertTransType
        // for the purposes of TransItem typing.
        return (((vttId >> 8) & 0xFF) == (CTVERSION - 1)) ?
                CertTransType.valueOf(vttId & 0xFF) : null;
    }

    /**
     * Create a specific subclass of TransItem from a
     * {@code SerializedTransItem} data block.  The SerializedTransItem
     * structure conforms to the following format:
     * <pre>
     * opaque SerializedTransItem<1..2^16-1>;
     * </pre>
     *
     * @param data a {@code ByteBuffer} positioned at the leading vector length
     *             for the {@code SerializedTransItem}
     *
     * @return a concrete instance of a {@code TransItem}.
     *
     * @throws IOException if any parsing errors occur during deserialization.
     */
    static TransItem getInstance(ByteBuffer data) throws IOException {
        int stiLen = Record.getInt16(data);          // serialized TI length

        // Slice the data so the constructor only needs to be concerned with
        // that specific TransItem data.  Advance the "data" ByteBuffer position
        // past that SerializedTransItem manually.
        ByteBuffer transItemData = data.slice(data.position(), stiLen);
        data.position(data.position() + stiLen);

        int vttId = Record.getInt16(transItemData);
        CertTransType vType = versTransTypeToCTT(vttId);
        return switch (vType) {
            case X509_ENTRY -> new X509EntryV2(transItemData);
            case PRECERT_ENTRY -> new PreCertEntryV2(transItemData);
            case X509_SCT -> new PreCertSctV2(transItemData);
            case PRECERT_SCT -> new X509CertSctV2(transItemData);
            case SIGNED_TREE_HEAD -> new SignedTreeHeadV2(transItemData);
            case CONSISTENCY_PROOF -> new ConsistencyProofV2(transItemData);
            case INCLUSION_PROOF -> new InclusionProofV2(transItemData);
            default -> new GenericTransItem(vttId, transItemData);
        };
    }

    /**
     * Parse a TransItemList as specified in RFC 9162.  A TransItemList has
     * the following data format:
     * <pre>
     * opaque SerializedTransItem<1..2^16-1>;
     *
     * struct {
     *     SerializedTransItem trans_item_list<1..2^16-1>
     * } TransItemList;
     * </pre>
     *
     * @param data the ByteBuffer containing the TransItemList data.  The
     *        position of the ByteBuffer must be at the start of
     *        the trans_item_list vector (the vector length).
     *
     * @return the {@code Set} of {@code CertTransElement} objects contained
     *         within the TransItemList.
     *
     * @throws SSLException if the TransItemList does not contain at least
     *         one {@code CertTransElement} of type {@code X509_SCT} or
     *         {@code PRECERT_SCT}.  This exception will also be thrown
     *         if the trans_item_list is empty.
     * @throws IOException if any parsing errors occur.
     */
    public static Set<CertTransElement> parseTransItemList(ByteBuffer data)
            throws IOException {
        boolean hasSct = false;
        int tiListLen = Record.getInt16(data);
        if (tiListLen <= 0) {
            throw new SSLException("Illegal trans_item_list length: " +
                    tiListLen);
        }
        int endPos = data.position() + tiListLen;
        if (endPos > data.limit()) {
            throw new IOException("trans_item_list vector length exceeds " +
                    "buffer limit: len = " + tiListLen + ", pos = " +
                    data.position() + ", lim = " + data.limit());
        }

        Set<CertTransElement> cteSet = new LinkedHashSet<>();
        while (data.position() <= endPos) {
            CertTransElement elem = TransItem.getInstance(data);
            hasSct |= (elem.getType() == CertTransType.PRECERT_SCT ||
                    elem.getType() == CertTransType.X509_SCT);
            cteSet.add(elem);
        }

        if (hasSct) {
            return cteSet;
        } else {
            throw new SSLException("Missing required signed certificate " +
                    "timestamp in TransItemList");
        }
    }
}

/**
 * Abstract class for the SignedCertTimestampDataV2 structure from RFC 9162.
 * This structure is encoded as follows:
 * <pre>
 * opaque LogID<2..127>;
 *
 * struct {
 *      LogID log_id;
 *      uint64 timestamp;
 *      Extension sct_extensions<0..2^16-1>;
 *      opaque signature<1..2^16-1>;
 * } SignedCertificateTimestampDataV2;
 * </pre>
 */
abstract class SignedCertTimestampV2 extends TransItem
        implements SignedCertificateTimestamp {
    protected final Instant timestamp;
    protected final byte[] logId;
    protected final Map<Integer, byte[]> sctExtensions;
    protected final byte[] signature;

    protected SignedCertTimestampV2(CertTransType type, ByteBuffer data)
            throws IOException {
        super(type);
        int dataStart = data.position() - 2;    // start of TransItem
        logId = Record.getBytes8(data);
        timestamp = Instant.ofEpochMilli(Record.getInt64(data));
        sctExtensions = Utilities.parseTlsExtensions(data);
        signature = Record.getBytes16(data);

        // Hold a copy of the encoded data
        copyEncodedBytes(dataStart, data);
    }

//    abstract byte[] encodeTBSCert(X509Certificate subjectCert)
//            throws IOException;

    @Override
    public byte[] getEncoded() throws IOException {
        if (this.encodedData == null) {
            HandshakeOutStream hos = new HandshakeOutStream(null);
            hos.putBytes8(logId);
            hos.putInt64(timestamp.toEpochMilli());
            hos.write(Utilities.encodeTlsExtensions(sctExtensions));
            this.encodedData = hos.toByteArray();
        }
        return this.encodedData.clone();
    }

    @Override
    public int getVersion() {
        return CTVERSION;
    }

    @Override
    public byte[] getLogId() {
        return logId.clone();
    }

    @Override
    public Instant getTimestamp() {
        return timestamp;
    }

    @Override
    public byte[] getSignature() {
        return signature.clone();
    }

    @Override
    public Map<Integer, byte[]> getExtensions() {
        Map<Integer, byte[]> retMap = new LinkedHashMap<>();
        sctExtensions.forEach((id, val) -> retMap.put(id, val.clone()));
        return retMap;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Type: ").append(ctType).append(" (Version ").
                append(getVersion()).append(")");
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
}


/**
 * Concrete SignedCertTimestampV2 class governing the "precert_sct_v2"
 * versioned type.
 */
final class PreCertSctV2 extends SignedCertTimestampV2 {
    PreCertSctV2(ByteBuffer data) throws IOException {
        super(CertTransType.PRECERT_SCT, data);
    }

    @Override
    public boolean verify(X509Certificate certificate, PublicKey issuerKey,
                          PublicKey logKey) throws SignatureException {
        return true;
    }

//    public void verify(PublicKey logKey, SignatureScheme scheme,
//                       X509Certificate cert, X509Certificate issuer)
//            throws SignatureException {
//        try {
//            super.verify(logKey, scheme, cert, issuer,
//                    new TransItem(TransItem.VersionedTransType.PRECERT_ENTRY_V2,
//                            new PreCertEntryV2(timestamp, cert, issuer,
//                                    sctExtensions)));
//        } catch (IOException ioe) {
//            throw new SignatureException(ioe);
//        }
//    }
}

/**
 * Concrete SignedCertTimestampV2 class governing the "x509_sct_v2"
 * versioned type.
 */
final class X509CertSctV2 extends SignedCertTimestampV2 {
    X509CertSctV2(ByteBuffer data) throws IOException {
        super(CertTransType.X509_SCT, data);
    }

    @Override
    public boolean verify(X509Certificate certificate, PublicKey issuerKey,
                          PublicKey logKey) throws SignatureException {
        return true;
    }

//    public void verify(PublicKey logKey, SignatureScheme scheme,
//                       X509Certificate cert, X509Certificate issuer)
//            throws SignatureException {
//        try {
//            super.verify(logKey, scheme, cert, issuer,
//                    new TransItem(TransItem.VersionedTransType.X509_ENTRY_V2,
//                            new X509EntryV2(timestamp, cert, issuer,
//                                    sctExtensions)));
//        } catch (IOException ioe) {
//            throw new SignatureException(ioe);
//        }
//    }
}

/**
 * Abstract class that defines the TimestampedCertEntryDataV2 TransItem
 * structure from RFC 9162.  This uses the same encoding for both X.509 and
 * pre-certificate sub-types:
 * <pre>
 * opaque TBSCertificate<1..2^24-1>;
 *
 * struct {
 *      uint64 timestamp;
 *      opaque issuer_key_hash<32..2^8-1>;
 *      TBSCertificate tbs_certificate;
 *      Extension sct_extensions<0..2^16-1>;
 * } TimestampedCertificateEntryDataV2;
 * </pre>
 */
abstract class TimestampedCertEntryV2 extends TransItem {
    protected final Instant timestamp;
    protected final byte[] issuerKeyHash;
    protected final X509CertInfo tbsCert;
    protected final Map<Integer, byte[]> entryExtensions;

    /**
     * Protected constructor for a {@code TimestampedCertEntryDataV2} object
     *
     * @param type the {@code CertTransType} corresponding to this
     *             {@code TransItem}.  This may be null in the case of
     *             experimental or private types.
     * @param data the {@code ByteBuffer} containing the encoded timestamped
     *             cert entry.
     *
     * @throws IOException if any parsing errors occur.
     */
    protected TimestampedCertEntryV2(CertTransType type, ByteBuffer data)
            throws IOException {
        super(type);
        int dataStart = data.position() - 2;    // start of TransItem
        timestamp = Instant.ofEpochMilli(Record.getInt64(data));
        issuerKeyHash = Record.getBytes8(data);
        try {
            tbsCert = new X509CertInfo(Record.getBytes24(data));
        } catch (CertificateParsingException cpe) {
            throw new IOException(cpe);
        }
        entryExtensions = Utilities.parseTlsExtensions(data);

        // Hold a copy of the encoded data
        copyEncodedBytes(dataStart, data);
    }

    @Override
    public byte[] getEncoded() throws IOException {
        if (this.encodedData == null) {
            HandshakeOutStream hos = new HandshakeOutStream(null);
            hos.putInt16(ctType.getId());         // versioned_type
            hos.putInt64(timestamp.toEpochMilli());
            hos.putBytes8(issuerKeyHash);
            try {
                hos.putBytes24(tbsCert.getEncodedInfo());
            } catch (CertificateEncodingException cex) {
                throw new IOException(cex);
            }
            hos.write(Utilities.encodeTlsExtensions(entryExtensions));
            this.encodedData = hos.toByteArray();
        }
        return this.encodedData.clone();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Type: ").append(ctType).append(" (Version ").
                append(getVersion()).append(")");
        sb.append("\nTimestamp: ").append(DateTimeFormatter.RFC_1123_DATE_TIME.
                format(timestamp.atOffset(ZoneOffset.UTC)));
        sb.append("\nIssuer Key Hash: ").append(
                Utilities.toHexString(issuerKeyHash));
        sb.append("\nTBSCertificate: {\n").append(
                Utilities.indent(tbsCert.toString())).append("\n}");
        sb.append("\nCT Extensions: { ");
        if (entryExtensions.isEmpty()) {
            sb.append("}");
        } else {
            entryExtensions.forEach((extId, extData) -> sb.append(
                    String.format("\n    Extension: (0x%04X), %d bytes",
                            extId, extData.length)));
            sb.append("\n}");
        }
        return sb.toString();
    }
}

/**
 * Concrete TimestampedCertEntryV2 class governing the "x509_entry_v2"
 * versioned type.
 */
final class X509EntryV2 extends TimestampedCertEntryV2 {
    X509EntryV2(ByteBuffer data) throws IOException {
        super(CertTransType.X509_ENTRY, data);
    }
}

/**
 * Concrete TimestampedCertEntryV2 class governing the "precert_entry_v2"
 * versioned type.
 */
final class PreCertEntryV2 extends TimestampedCertEntryV2 {
    PreCertEntryV2(ByteBuffer data) throws IOException {
        super(CertTransType.PRECERT_ENTRY, data);
    }

    byte[] encodeTBSCert(X509Certificate subjCert) throws IOException {
        DerOutputStream tbsCertOutStream = new DerOutputStream();
        DerOutputStream tbsItems = new DerOutputStream();
        DerInputStream dis;
        try {
            dis = new DerInputStream(subjCert.getTBSCertificate());
        } catch (CertificateEncodingException exc) {
            throw new IOException(exc);
        }

        DerValue[] dvOutSeq = dis.getSequence(10);
        for (DerValue dv : dvOutSeq) {
            if (dv.isContextSpecific((byte)3) && dv.isConstructed()) {
                DerOutputStream modExts = filterExtensions(dv, List.of(
                        TransparencyInformation_Id,
                        SignedCertificateTimestampList_Id));
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
            if (!oidsToFilter.contains(singleExtDis.getOID())) {
                extsItems.putDerValue(dv);
            }
        }

        // Write the outer SEQUENCE tag for the Extensions
        extsOuterSeq.write(DerValue.tag_Sequence, extsItems);
        return extsOuterSeq;
    }
}

///**
// * Abstract class for the SignedCertificateTimestampDataV2 structure from
// * RFC 9162. This structure is encoded as follows:
// *
// *      struct {
// *          LogID log_id;
// *          uint64 timestamp;
// *          Extension sct_extensions<0..2^16-1>;
// *          opaque signature<0..2^16-1>;
// *      } SignedCertificateTimestampDataV2;
// */
//abstract class SignedCertTimestampV2 extends TransItem {
//    final byte[] logId;
//    final Date timestamp;
//    final Map<Integer, CtExtension> sctExtensions = new LinkedHashMap<>();
//    final byte[] signature;
//
//    protected SignedCertTimestampDataV2(ByteBuffer data) throws IOException {
//        super(data);
//        logId = new V2LogID(data);
//        timestamp = new Date(data.getLong());
//        int endOfExts = Math.addExact(data.position(),
//                    Record.getInt16(data));
//        while (data.position() < endOfExts) {
//            CtExtension exten = new CtExtension(data);
//            sctExtensions.put(exten.extensionType, exten);
//        }
//        signature = Record.getBytes16(data);
//    }
//
//    protected void verify(PublicKey logKey, SignatureScheme scheme,
//            X509Certificate cert, X509Certificate issuer, TransItem sigInput)
//            throws SignatureException {
//         try {
//            Signature verifier = scheme.getVerifier(logKey);
//            verifier.update(sigInput.encode());
//            verifier.verify(signature);
//        } catch (GeneralSecurityException | IOException exc) {
//            throw new SignatureException(exc);
//        }
//    }
//
//    @Override
//    byte[] encode() throws IOException {
//        if (this.serializedData == null) {
//            HandshakeOutStream hos = new HandshakeOutStream(null);
//            hos.write(logId.encode());
//            hos.putInt64(timestamp.getTime());
//            ByteArrayOutputStream extStream = new ByteArrayOutputStream();
//            for (CtExtension extVal : sctExtensions.values()) {
//                extStream.write(extVal.encode());
//            }
//            hos.putBytes16(extStream.toByteArray());
//            hos.putBytes16(signature);
//            this.serializedData = hos.toByteArray();
//        }
//        return this.serializedData.clone();
//    }
//
//    @Override
//    public String toString() {
//        HexDumpEncoder hexDump = new HexDumpEncoder();
//        SimpleDateFormat dateFormat =
//                new SimpleDateFormat("MMM dd, YYYY HH:mm:ss.SSS zzz");
//        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
//        StringBuilder sb = new StringBuilder();
//        sb.append("Log ID: ").append(logId).append("\n");
//        sb.append("Timestamp: ").append(dateFormat.format(timestamp)).
//                append("\n");
//        sb.append("CT Extensions:\n");
//        sctExtensions.forEach((extId, sctExt) ->
//                sb.append(sctExt).append("\n"));
//        sb.append("Signature:\n").append(hexDump.encode(signature));
//        return sb.toString();
//    }
//}
//
//
///**
// * Concrete SignedCertTimestampDataV2 class governing the "precert_sct_v2"
// * versioned type.
// */
//final class PreCertSCTV2 extends SignedCertTimestampV2 {
//    PreCertSCTV2(ByteBuffer data) throws IOException {
//        super(data);
//    }
//
//    public void verify(PublicKey logKey, SignatureScheme scheme,
//                       X509Certificate cert, X509Certificate issuer)
//            throws SignatureException {
//        try {
//            super.verify(logKey, scheme, cert, issuer,
//                    new TransItem(TransItem.VersionedTransType.PRECERT_ENTRY_V2,
//                            new PreCertEntryV2(timestamp, cert, issuer,
//                                    sctExtensions)));
//        } catch (IOException ioe) {
//            throw new SignatureException(ioe);
//        }
//    }
//}
//
///**
// * Concrete SignedCertTimestampDataV2 class governing the "x509_sct_v2"
// * versioned type.
// */
//final class X509SCTV2 extends SignedCertTimestampV2 {
//    X509SCTV2(ByteBuffer data) throws IOException {
//        super(data);
//    }
//
//    public void verify(PublicKey logKey, SignatureScheme scheme,
//                       X509Certificate cert, X509Certificate issuer)
//            throws SignatureException {
//        try {
//            super.verify(logKey, scheme, cert, issuer,
//                    new TransItem(TransItem.VersionedTransType.X509_ENTRY_V2,
//                            new X509EntryV2(timestamp, cert, issuer,
//                                    sctExtensions)));
//        } catch (IOException ioe) {
//            throw new SignatureException(ioe);
//        }
//    }
//}

/**
 * Implementation for the SignedTreeHeadDataV2 CT structure.
 * The format of this structure is as follows:
 * <pre>
 * opaque LogID<2..127>;
 * opaque NodeHash<32..2^16-1>;
 *
 * struct {
 *      LogID log_id;
 *      TreeHeadDataV2 tree_head {
 *          uint64 timestamp;
 *          uint64 tree_size;
 *          NodeHash root_hash;
 *          Extension sth_extensions<0..2^16-1>;
 *      }
 *      opaque signature<0..2^16-1>;
 * } SignedTreeHeadDataV2;
 * </pre>
 */
final class SignedTreeHeadV2 extends TransItem {
    final byte[] logId;
    final Instant timestamp;
    final long treeSize;
    final byte[] rootHash;
    final byte[] signature;
    final Map<Integer, byte[]> sthExtensions;

    SignedTreeHeadV2(ByteBuffer data) throws IOException {
        int dataStart = data.position() - 2;    // start of TransItem
        super(CertTransType.SIGNED_TREE_HEAD);
        logId = Record.getBytes8(data);
        timestamp = Instant.ofEpochMilli(Record.getInt64(data));
        treeSize = Record.getInt64(data);
        rootHash = Record.getBytes8(data);
        sthExtensions = Utilities.parseTlsExtensions(data);
        signature = Record.getBytes16(data);

        // Hold a copy of the encoded data
        copyEncodedBytes(dataStart, data);
    }

    // TBD
    public void verify(PublicKey logKey) throws SignatureException {
        // Compute signature over treeHead object encoding
    }

    @Override
    public byte[] getEncoded() throws IOException {
        if (this.encodedData == null) {
            HandshakeOutStream hos = new HandshakeOutStream(null);
            hos.putInt16(ctType.getId());         // versioned_type
            hos.write(logId);
            hos.putInt64(timestamp.toEpochMilli());
            hos.putInt64(treeSize);
            hos.putBytes8(rootHash);
            hos.write(Utilities.encodeTlsExtensions(sthExtensions));
            hos.putBytes16(signature);
            this.encodedData = hos.toByteArray();
        }
        return this.encodedData.clone();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Type: ").append(ctType).append(" (Version ").
                append(getVersion()).append(")");
        sb.append("\nLog ID: ").append(Utilities.toHexString(logId));
        sb.append("\nTimestamp: ").append(DateTimeFormatter.RFC_1123_DATE_TIME.
                format(timestamp.atOffset(ZoneOffset.UTC)));
        sb.append("\nTree Size: ").append(treeSize);
        sb.append("\nRoot Hash: ").append(Utilities.toHexString(rootHash));
        sb.append("\nCT Extensions: { ");
        if (sthExtensions.isEmpty()) {
            sb.append("}");
        } else {
            sthExtensions.forEach((extId, extData) ->
                sb.append(String.format("\n    Extension: (0x%04X), %d bytes",
                        extId, extData.length)));
            sb.append("\n}");
        }
        sb.append("\nSignature (not shown, ").append(signature.length).
                append(" bytes)");
        return sb.toString();
    }
}

/**
 * Implementation for the ConsistencyProofDataV2 CT structure.
 * The format of this structure is as follows:
 * <pre>
 * opaque LogID<2..127>;
 * opaque NodeHash<32..2^16-1>;
 *
 * struct {
 *      LogID log_id;
 *      uint64 tree_size_1;
 *      uint64 tree_size_2;
 *      NodeHash consistency_path<1..2^16-1>;
 * } ConsistencyProofDataV2;
 * </pre>
 */
final class ConsistencyProofV2 extends TransItem {
    final byte[] logId;
    final long treeSizeOne;
    final long treeSizeTwo;
    List<byte[]> consistencyPath = new ArrayList<>();

    ConsistencyProofV2(ByteBuffer data) throws IOException {
        super(CertTransType.CONSISTENCY_PROOF);
        int dataStart = data.position() - 2;    // start of TransItem
        logId = Record.getBytes8(data);
        treeSizeOne = Record.getInt64(data);
        treeSizeTwo = Record.getInt64(data);
        int consPathLen = Record.getInt16(data);
        ByteBuffer consPathBuf = data.slice(data.position(), consPathLen);
        while (consPathBuf.hasRemaining()) {
            consistencyPath.add(Record.getBytes8(consPathBuf));
        }
        data.position(data.position() + consPathLen);

        // Hold a copy of the encoded data
        copyEncodedBytes(dataStart, data);
    }

    @Override
    public byte[] getEncoded() throws IOException {
        if (this.encodedData == null) {
            HandshakeOutStream hos = new HandshakeOutStream(null);
            hos.putInt16(ctType.getId());         // versioned_type
            hos.write(logId);
            hos.putInt64(treeSizeOne);
            hos.putInt64(treeSizeTwo);
            HandshakeOutStream pathStream = new HandshakeOutStream(null);
            for (byte[] nodeHash : consistencyPath) {
                pathStream.putBytes8(nodeHash);
            }
            hos.putBytes16(pathStream.toByteArray());
            this.encodedData = hos.toByteArray();
        }
        return this.encodedData.clone();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Type: ").append(ctType).append(" (Version ").
                append(getVersion()).append(")");
        sb.append("\nLog ID: ").append(Utilities.toHexString(logId));
        sb.append("\nTree Size One: ").append(treeSizeOne);
        sb.append("\nTree Size Two: ").append(treeSizeTwo);
        sb.append("\nConsistency Path: { ");
        if (consistencyPath.isEmpty()) {
            sb.append("}");
        } else {
            consistencyPath.forEach(nodeHash -> sb.append("\n    Node Hash: ").
                    append(Utilities.toHexString(nodeHash)));
            sb.append("\n}");
        }
        return sb.toString();
    }
}

/**
 * Implementation for the InclusionProofDataV2 CT structure.
 * The format of this structure is as follows:
 * <pre>
 * opaque LogID<2..127>;
 * opaque NodeHash<32..2^16-1>;
 *
 * struct {
 *      LogID log_id;
 *      uint64 tree_size;
 *      uint64 leaf_index;
 *      NodeHash inclusion_path<1..2^16-1>;
 * } InclusionProofDataV2;
 * </pre>
 */
final class InclusionProofV2 extends TransItem {
    final byte[] logId;
    final long treeSize;
    final long leafIndex;
    List<byte[]> inclusionPath = new ArrayList<>();

    InclusionProofV2(ByteBuffer data) throws IOException {
        super(CertTransType.INCLUSION_PROOF);
        int dataStart = data.position() - 2;    // start of TransItem
        logId = Record.getBytes8(data);
        treeSize = Record.getInt64(data);
        leafIndex = Record.getInt64(data);
        int inclPathLen = Record.getInt16(data);
        ByteBuffer inclPathBuf = data.slice(data.position(), inclPathLen);
        while (inclPathBuf.hasRemaining()) {
            inclusionPath.add(Record.getBytes8(inclPathBuf));
        }
        data.position(data.position() + inclPathLen);

        // Hold a copy of the encoded data
        copyEncodedBytes(dataStart, data);
    }

    @Override
    public byte[] getEncoded() throws IOException {
        if (this.encodedData == null) {
            HandshakeOutStream hos = new HandshakeOutStream(null);
            hos.putInt16(ctType.getId());         // versioned_type
            hos.write(logId);
            hos.putInt64(treeSize);
            hos.putInt64(leafIndex);
            HandshakeOutStream pathStream = new HandshakeOutStream(null);
            for (byte[] nodeHash : inclusionPath) {
                pathStream.putBytes8(nodeHash);
            }
            hos.putBytes16(pathStream.toByteArray());
            this.encodedData = hos.toByteArray();
        }
        return this.encodedData.clone();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Type: ").append(ctType).append(" (Version ").
                append(getVersion()).append(")");
        sb.append("\nLog ID: ").append(Utilities.toHexString(logId));
        sb.append("\nTree Size: ").append(treeSize);
        sb.append("\nLeaf Index: ").append(leafIndex);
        sb.append("\nInclusion Path: { ");
        if (inclusionPath.isEmpty()) {
            sb.append("}");
        } else {
            inclusionPath.forEach(nodeHash -> sb.append("\n    Node Hash: ").
                    append(Utilities.toHexString(nodeHash)));
            sb.append("\n}");
        }
        return sb.toString();
    }
}

/**
 * Concrete subclass of TransItem to support new/unknown TransItem types
 * found during parsing.
 */
final class GenericTransItem extends TransItem {

    private final int vttId;

    GenericTransItem(int id, ByteBuffer data) {
        super(null);
        vttId = id;
        int dataStart = data.position() - 2;    // start of TransItem
        // Hold a copy of the encoded data
        copyEncodedBytes(dataStart, data);
    }

    @Override
    public byte[] getEncoded() throws IOException {
        return (this.encodedData != null) ? encodedData.clone() : new byte[0];
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Type [Unknown]: ").append(vttId).append(" (Version ").
                append(getVersion()).append(")");
        sb.append("\nData (not shown, ").append(encodedData.length).
                append(" bytes]");
        return sb.toString();
    }
}
