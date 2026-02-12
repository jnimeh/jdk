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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import static sun.security.ssl.SSLExtension.CH_SIGNED_CERT_TIMESTAMP;
import static sun.security.ssl.SSLExtension.CR_SIGNED_CERT_TIMESTAMP;
import static sun.security.ssl.SSLExtension.CT_SIGNED_CERT_TIMESTAMP;
import static sun.security.ssl.SSLExtension.SH_SIGNED_CERT_TIMESTAMP;
import sun.security.ssl.SSLExtension.ExtensionConsumer;
import sun.security.ssl.SSLExtension.SSLExtensionSpec;
import sun.security.ssl.SSLHandshake.HandshakeMessage;
import sun.security.ssl.SignedCertTimestampV1.X509CertSctV1;

import javax.net.ssl.SignedCertificateTimestamp;

/**
 * Handling logic for the signed_certificate_timestamp TLS extension.
 */
final class SignedCertTimestampExtension {
    static final HandshakeProducer chNetworkProducer =
            new CHSignedCertTimestampProducer();
    static final ExtensionConsumer chOnLoadConsumer =
            new CHSignedCertTimestampConsumer();

    static final HandshakeProducer shNetworkProducer =
            new SHSignedCertTimestampProducer();
    static final ExtensionConsumer shOnLoadConsumer =
            new SHSignedCertTimestampConsumer();

    static final HandshakeProducer ctNetworkProducer =
            new CTSignedCertTimestampProducer();
    static final ExtensionConsumer ctOnLoadConsumer =
            new CTSignedCertTimestampConsumer();

    static final SSLStringizer signedCertTimestampStringizer =
            new SignedCertTimestampStringizer();

    /**
     * The "signed_certificate_timestamp" extension.
     * <p>
     * RFC 6962 defines the TLS extension,"signed_certificate_timestamp"
     * (type 0x12), which allows the client to request signed certificate
     * timestamps from the server via any of the three defined mechanisms.
     * The handling logic in this file covers sending the ClientHello extension
     * and processing the SCTs returned in the ServerHello (TLS <= 1.2) or
     * Certificate (TLS >= 1.3) messages.  Processing for SCTs delivered via
     * X.509 certificates and OCSP responses are handled in other parts of
     * the handshaking code.
     * <p>
     * The "extension data" field of this extension contains a
     * "SignedCertificateTimestamp" structure:
     * <pre>
     * struct {
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
     *         CtExtensions extensions;
     *      };
     * } SignedCertificateTimestamp;
     * </pre>
     * The spec itself handles a SignedCertificateTimestampList, a vector
     * consisting of one or more SerializedSCT structures:
     * <pre>
     * opaque SerializedSCT<1..2^16-1>;
     *
     * struct {
     *      SerializedSCT sct_list <1..2^16-1>;
     * } SignedCertificateTimestampList;
     * </pre>
     */
    static final class SignedCertTimestampSpec implements SSLExtensionSpec {
        static final SignedCertTimestampSpec NOMINAL =
                new SignedCertTimestampSpec(Collections.emptyList());

        final List<SignedCertificateTimestamp> sigCertTsList;

        private SignedCertTimestampSpec(
                List<SignedCertificateTimestamp> sctList) {
            this.sigCertTsList = sctList;
        }

        private SignedCertTimestampSpec(HandshakeContext hc, ByteBuffer buffer)
                throws IOException {
            //TODO
            sigCertTsList = List.of();
//            try {
//                this.sigCertTsList = new ArrayList<>(
//                        SignedCertificateTimestamp.getSCTList(
//                                X509CertSctV1.class, buffer));
//            } catch (IOException ioe) {
//                throw hc.conContext.fatal(Alert.DECODE_ERROR, ioe);
//            }
        }

        @Override
        public String toString() {
            if (this != NOMINAL) {
                StringBuilder sb = new StringBuilder();
                int numElem = sigCertTsList.size();
                sb.append("Signed Certificate Timestamp List (").
                        append(numElem).append(" ").
                        append(numElem == 1 ? "entry" : "entries").
                        append(")\n");
                sigCertTsList.forEach(sct -> {
                    sb.append(sct).append("\n\n");
                });
                sb.append("\n");
                return sb.toString();
            } else {
                return "<empty>";
            }
        }
    }

    private static final
            class SignedCertTimestampStringizer implements SSLStringizer {
        @Override
        public String toString(HandshakeContext hc, ByteBuffer buffer) {
            try {
                if (buffer.hasRemaining()) {
                    // For SCT display purposes, the log entry type does not
                    // matter.
                    return (new SignedCertTimestampSpec(hc, buffer)).
                            toString();
                } else {
                    return SignedCertTimestampSpec.NOMINAL.toString();
                }
            } catch (IOException ioe) {
                // For debug logging only, so please swallow exceptions.
                return ioe.getMessage();
            }
        }
    }

    /**
     * Network data producer of a "signed_certificate_timestamp" extension in
     * the ClientHello handshake message.
     */
    private static final class CHSignedCertTimestampProducer
            implements HandshakeProducer {
        // Prevent instantiation of this class.
        private CHSignedCertTimestampProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;
            if (!SSLConfiguration.enableClientCertTrans) {
                return null;
            }

            if (!chc.sslConfig.isAvailable(CH_SIGNED_CERT_TIMESTAMP)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " +
                            CH_SIGNED_CERT_TIMESTAMP.name);
                }
                return null;
            }

            // Produce the extension.  For the client hello, the extension
            // should have an empty extension_data field.
            byte[] extData = new byte[0];

            // Update the context.
            chc.handshakeExtensions.put(CH_SIGNED_CERT_TIMESTAMP,
                    SignedCertTimestampSpec.NOMINAL);

            return extData;
        }
    }

    /**
     * Network data consumer of a "signed_certificate_timestamp" extension in
     * the ClientHello handshake message.
     */
    private static final
            class CHSignedCertTimestampConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private CHSignedCertTimestampConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
            HandshakeMessage message, ByteBuffer buffer) throws IOException {

            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            if (!shc.sslConfig.isAvailable(CH_SIGNED_CERT_TIMESTAMP)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " +
                        CH_SIGNED_CERT_TIMESTAMP.name);
                }
                return;     // ignore the extension
            }

            // The extension should have a zero length extension_data segment.
            if (buffer.hasRemaining()) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Invalid signed_certificate_timestamp extension in " +
                        "ServerHello message: the extension data " +
                        "must be empty");
            }

            // Update the context.
            shc.handshakeExtensions.put(CH_SIGNED_CERT_TIMESTAMP, null);

            // Since we've received a legitimate signed_certificate_timestamp
            // in the ServerHello, set CT to be active.
            //shc.certTransActive = true;

            // No impact on session resumption.
        }
    }

    /**
     * Network data producer of a "signed_certificate_timestamp" extension in
     * the ServerHello handshake message.
     */
    private static final
            class SHSignedCertTimestampProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private SHSignedCertTimestampProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in client side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // In response to "signed_certificate_timestamp" extension
            // request only.
            if (!shc.handshakeExtensions.containsKey(
                    CH_SIGNED_CERT_TIMESTAMP)) {
                // Ignore, no signed_certificate_timestamp extension requested.
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Ignore unavailable extension: " +
                            CH_SIGNED_CERT_TIMESTAMP.name);
                }

                return null;        // ignore the extension
            }

            // Is it a session resuming?
            if (shc.isResumption) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest(
                        "No status_request response for session resuming");
                }

                return null;        // ignore the extension
            }

            // For right now, the server-side application of SCTs into
            // the ServerHello message is not complete.  So we'll
            // return null for right now and not do CT.  Eventually extData
            // will contain the serialized SignedCertificateTimestampList
            byte[] extData = null;
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.finest("Warning: ServerHello CT delivery " +
                        "currently not implemented");
            }

            return extData;
        }
    }

    /**
     * Network data consumer of a "signed_certificate_timestamp" extension in
     * the ServerHello handshake message.
     */
    private static final
            class SHSignedCertTimestampConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private SHSignedCertTimestampConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
            HandshakeMessage message, ByteBuffer buffer) throws IOException {

            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // In response to "signed_certificate_timestamp" extension
            // data only.
            if (!chc.handshakeExtensions.containsKey(CH_SIGNED_CERT_TIMESTAMP)) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Unexpected signed_certificate_timestamp extension " +
                                "in ServerHello");
            }

            // Parse the extension.  Since these SCTs come from a TLS extension
            // they should be constructed from the finished X.509 certificate.
            SignedCertTimestampSpec sctSpec = new SignedCertTimestampSpec(
                    chc, buffer);

            // Update the context.  We will need to access this SCT spec
            // after we receive the certificate so it can be properly
            // added to the cache.
            chc.handshakeExtensions.put(SH_SIGNED_CERT_TIMESTAMP, sctSpec);

            // Since we've received a legitimate signed_certificate_timestamp
            // in the ServerHello we can activate the CT feature flag.
            //chc.certTransActive = true;
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.finest("Received " + sctSpec.sigCertTsList.size() +
                        " SCT entries from ServerHello extension");
            }

            // No impact on session resumption.
        }
    }

    private static final
            class CTSignedCertTimestampProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private CTSignedCertTimestampProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext)context;
            byte[] producedData = null;

            // TODO:
            // We currently don't have the implementation for server-side
            // inclusion of the SCTs in the TLS 1.3 certificate message.
            // This will require additional design.  For now, include nothing.

            // Clear the pinned CertificateEntry from the context
            //shc.currentCertEntry = null;
            return producedData;
        }
    }

    private static final
        class CTSignedCertTimestampConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private CTSignedCertTimestampConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                HandshakeMessage message, ByteBuffer buffer) throws IOException {
            // The consumption happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // Parse the extension.
            SignedCertTimestampSpec sctSpec;
            try {
                // These SCTs will be in response to TLS hello extensions and
                // therefore should use the completed X.509 certificate as
                // input.
                sctSpec = new SignedCertTimestampSpec(chc, buffer);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.DECODE_ERROR, ioe);
            }

            // Get the SCT list from the spec.  Then all we need to do is
            // add the SCTs to the end of the handshake context's sctList
            // collection.  Processing will take place once all SCTs have been
            // retrieved by every method the server employs.
            if (!chc.isResumption) {
                // Update the context.  We will need to access this SCT spec
                // after we receive the certificate so it can be properly
                // added to the cache.
                chc.handshakeExtensions.put(CT_SIGNED_CERT_TIMESTAMP, sctSpec);
                //chc.certTransActive = true;
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest("Received " +
                            sctSpec.sigCertTsList.size() +
                            " SCT entries from Certificate Message extension");
                }
            } else {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest("Ignoring SCT data on resumed session");
                }
            }
        }
    }
}
