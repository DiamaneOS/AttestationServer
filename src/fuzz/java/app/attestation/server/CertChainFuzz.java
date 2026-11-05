package app.attestation.server;

import app.attestation.server.attestation.AuthorizationList;
import app.attestation.server.attestation.ParsedAttestationRecord;
import app.attestation.server.attestation.RootOfTrust;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.common.primitives.Bytes;

import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// One certificate of a valid chain replaced by the input, checked by the stateless verification
// with the test root as the only manufacturer root.
//
// Input: byte 0 bit 0 picks the chain (0: profile 1 under the test root, 1: profile 2) and bit 1
// the mode. Mode 0: byte 1 picks the position and the rest is the DER certificate put there. Mode 1:
// byte 1 picks the leaf or the attest key certificate and the rest is its attestation extension,
// which the harness signs with the issuer's test key, so the policy checks behind the signatures see
// arbitrary attestation data.
//
// Invariants: the X.509 parser, the attestation extension parser and, for a verified chain, the
// review flags raise only their checked exceptions. A chain is accepted only if every certificate's signed part (TBS) is
// the original's, and the trust profile follows the root: no profile 2 result for a chain under a
// manufacturer root and no profile 1 result for any other chain. A re-signed chain is accepted only
// if its leaf attests what the policy requires: locked, the expected boot state and key, hardware
// security level, the Auditor package and signer, generated signing key, versions at the minimum.
public final class CertChainFuzz {
    private static final List<Certificate[]> chains = new ArrayList<>();
    private static final List<FuzzFixture> fixtures = new ArrayList<>();
    private static final List<byte[]> seeds = new ArrayList<>();
    private static Method verifyStateless;
    private static Method profile2Device;
    private static TrustConfig trust;
    private static byte[][] roots;

    public static void fuzzerInitialize() throws Exception {
        FuzzFixture.installTestRoot();
        trust = FuzzFixture.trust();
        roots = new byte[][]{FuzzFixture.testRootEncoded()};
        verifyStateless = AttestationProtocol.class.getDeclaredMethod("verifyStateless", Certificate[].class,
                AttestationProtocol.PendingChallenge.class, boolean.class, byte[][].class, TrustConfig.class);
        verifyStateless.setAccessible(true);
        for (final boolean profile1 : new boolean[]{true, false}) {
            final FuzzFixture fixture = new FuzzFixture(profile1 ? "chain p1" : "chain p2", profile1);
            chains.add(fixture.chain());
            fixtures.add(fixture);
        }
        profile2Device = verifyStateless.getReturnType().getDeclaredMethod("profile2Device");
        profile2Device.setAccessible(true);
        for (int c = 0; c < chains.size(); c++) {
            if (verify(chains.get(c)) == null) {
                throw new IllegalStateException("fixture chain " + c + " refused");
            }
            for (int i = 0; i < chains.get(c).length; i++) {
                seeds.add(Bytes.concat(new byte[]{(byte) c, (byte) i}, chains.get(c)[i].getEncoded()));
            }
            for (int i = 0; i < 2; i++) {
                final byte[] wrapped = ((X509Certificate) chains.get(c)[i]).getExtensionValue(Profile2.KEY_DESCRIPTION_OID);
                seeds.add(Bytes.concat(new byte[]{(byte) (c | 2), (byte) i},
                        org.bouncycastle.asn1.ASN1OctetString.getInstance(wrapped).getOctets()));
            }
        }
    }

    public static List<byte[]> seeds() throws Exception {
        fuzzerInitialize();
        return seeds;
    }

    public static void fuzzerTestOneInput(final byte[] data) throws Exception {
        if (data.length < 2) {
            return;
        }
        final int c = data[0] & 1;
        final Certificate[] original = chains.get(c);
        if ((data[0] & 2) != 0) {
            resigned(c, data[1] & 1, Arrays.copyOfRange(data, 2, data.length));
            return;
        }
        final int position = (data[1] & 0xff) % original.length;
        final byte[] der = Arrays.copyOfRange(data, 2, data.length);

        final X509Certificate certificate;
        try {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (final CertificateException e) {
            return;
        }
        try {
            ParsedAttestationRecord.createParsedAttestationRecord(List.of(certificate));
        } catch (final java.io.IOException | ParsedAttestationRecord.KeyDescriptionMissingException e) {
            // refused as malformed or absent
        }

        final Certificate[] chain = original.clone();
        chain[position] = certificate;
        final Object verified = verify(chain);
        if (verified == null) {
            return;
        }
        // as in production, only for a chain whose attestation extensions parsed
        Profile2.reviewFlags(chain, 1000);
        for (int i = 0; i < chain.length; i++) {
            if (!Arrays.equals(((X509Certificate) chain[i]).getTBSCertificate(),
                    ((X509Certificate) original[i]).getTBSCertificate())) {
                throw new AssertionError("accepted a chain with a changed signed part at " + i);
            }
        }
        final boolean manufacturerRooted = Arrays.equals(chain[chain.length - 1].getEncoded(), roots[0]);
        if (manufacturerRooted == (profile2Device.invoke(verified) != null)) {
            throw new AssertionError("trust profile does not follow the root");
        }
    }

    private static void resigned(final int c, final int position, final byte[] keyDescription) throws Exception {
        final Certificate[] chain = chains.get(c).clone();
        chain[position] = fixtures.get(c).resigned(position, keyDescription);
        final Object verified = verify(chain);
        if (verified == null) {
            return;
        }
        Profile2.reviewFlags(chain, 1000);
        final ParsedAttestationRecord record = ParsedAttestationRecord.createParsedAttestationRecord(
                List.of((X509Certificate) chain[0]));
        final var root = record.teeEnforced.rootOfTrust.orElseThrow();
        final var application = record.softwareEnforced.attestationApplicationId.orElseThrow();
        final boolean profile1 = c == 0;
        final String bootKey = com.google.common.io.BaseEncoding.base16().encode(root.verifiedBootKey);
        if (!root.deviceLocked
                || root.verifiedBootState != (profile1 ? RootOfTrust.VerifiedBootState.VERIFIED
                        : RootOfTrust.VerifiedBootState.SELF_SIGNED)
                || !bootKey.equals(profile1 ? FuzzFixture.profile1BootKey()
                        : com.google.common.io.BaseEncoding.base16().encode(FuzzFixture.TEST_AVB_KEY))
                || record.attestationSecurityLevel == ParsedAttestationRecord.SecurityLevel.SOFTWARE
                || record.keymasterSecurityLevel != record.attestationSecurityLevel
                || application.packageInfos.size() != 1 || !application.packageInfos.get(0).packageName.equals("de.diamaneos.auditor")
                || application.signatureDigests.size() != 1 || !Arrays.equals(application.signatureDigests.get(0), FuzzFixture.TEST_AUDITOR_SIGNER)
                || application.packageInfos.get(0).version < 89
                || !record.teeEnforced.purpose.equals(java.util.Set.of(
                        AuthorizationList.OperationPurpose.SIGN,
                        AuthorizationList.OperationPurpose.VERIFY))
                || record.teeEnforced.origin.orElse(null) != AuthorizationList.KeyOrigin.GENERATED
                || record.teeEnforced.allApplications
                || record.teeEnforced.osVersion.orElse(0) < 140000
                || record.teeEnforced.osPatchLevel.orElse(0) < 202505
                || root.verifiedBootHash.isEmpty()) {
            throw new AssertionError("accepted a leaf the policy refuses");
        }
    }

    // The Verified result, or null if refused. Unchecked exceptions escape.
    private static Object verify(final Certificate[] chain) throws Exception {
        try {
            return verifyStateless.invoke(null, chain,
                    new AttestationProtocol.PendingChallenge(System.currentTimeMillis() - 1000, 1), false,
                    roots, trust);
        } catch (final InvocationTargetException e) {
            if (e.getCause() instanceof GeneralSecurityException) {
                return null;
            }
            throw (Exception) e.getCause();
        }
    }
}
