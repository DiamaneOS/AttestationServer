package app.attestation.server;

import com.google.common.collect.ImmutableList;

import org.bouncycastle.asn1.ASN1Primitive;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import app.attestation.server.attestation.RootOfTrust;

// Trust profile 2, for devices whose secure hardware gives no manufacturer-rooted chain. The
// first pairing is trusted on the user's confirmation and must match an official release
// exactly. Later checks are pinned to it like any other pairing.
final class Profile2 {
    static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final String KEY_USAGE_OID = "2.5.29.15";
    private static final String ECDSA_SHA256_OID = "1.2.840.10045.4.3.2";
    // fresh key, pairing attest key, local root attest key without attestation data
    static final int CHAIN_LENGTH = 3;
    static final long CHALLENGE_LIFETIME_MS = 30 * 1000;
    // faster than a phone generates three hardware keys and answers over the network. A real FP6
    // took 0.28 s with the server on the same desk and 0.6 to 1 s over the internet.
    static final long FAST_RESPONSE_MS = 100;

    record Evidence(String verifiedBootKey, String verifiedBootHash, boolean deviceLocked,
            RootOfTrust.VerifiedBootState verifiedBootState, int securityLevel, int osVersion,
            int osPatchLevel, int vendorPatchLevel, int bootPatchLevel, int attestationVersion,
            int keyMintVersion) {}

    // No accepted release list is loaded. A server problem, so nothing is recorded or alerted.
    static final class ReleaseListUnavailableException extends java.io.IOException {
        ReleaseListUnavailableException() {
            super("no release list loaded");
        }
    }

    // Thrown for a paired device whose authenticated report breaks the release list policy
    static final class PolicyException extends GeneralSecurityException {
        PolicyException(final String message) {
            super(message);
        }
    }

    private Profile2() {}

    static void checkChainShape(final Certificate[] chain) throws GeneralSecurityException {
        if (chain.length != CHAIN_LENGTH
                || ((X509Certificate) chain[CHAIN_LENGTH - 1]).getExtensionValue(KEY_DESCRIPTION_OID) != null) {
            throw new GeneralSecurityException("root certificate is not a valid key attestation root");
        }
    }

    static TrustConfig.Device device(final TrustConfig config, final Evidence evidence)
            throws GeneralSecurityException {
        if (!evidence.deviceLocked) {
            throw new GeneralSecurityException("device is not locked");
        }
        if (evidence.verifiedBootState != RootOfTrust.VerifiedBootState.SELF_SIGNED) {
            throw new GeneralSecurityException("verified boot state is not self signed");
        }
        final List<TrustConfig.Device> devices =
                config.devicesFor(evidence.verifiedBootKey, evidence.securityLevel);
        if (devices.isEmpty()) {
            throw new GeneralSecurityException("invalid verified boot key fingerprint: " + evidence.verifiedBootKey);
        }
        return devices.get(0);
    }

    // Every reported value must equal the official release with this boot hash.
    static ReleaseList.Release match(final ReleaseList list, final TrustConfig.Device device,
            final Evidence evidence) throws GeneralSecurityException {
        final ReleaseList.Release release = list == null ? null
                : list.find(device.id(), evidence.verifiedBootKey, evidence.verifiedBootHash);
        if (release == null) {
            throw new PolicyException("verified boot hash is not an official release: "
                    + evidence.verifiedBootHash);
        }
        if (release.osVersion() != evidence.osVersion
                || release.osPatchLevel() != evidence.osPatchLevel
                || release.vendorPatchLevel() != evidence.vendorPatchLevel
                || release.bootPatchLevel() != evidence.bootPatchLevel
                || release.attestationVersion() != evidence.attestationVersion
                || release.keyMintVersion() != evidence.keyMintVersion) {
            throw new PolicyException("reported versions do not match official release "
                    + release.build());
        }
        return release;
    }

    static void checkFreshness(final long challengeAgeMs, final long lifetimeMs)
            throws GeneralSecurityException {
        if (challengeAgeMs < 0 || challengeAgeMs > lifetimeMs) {
            throw new GeneralSecurityException("challenge expired");
        }
    }

    // Plausibility checks against how Android Keystore encodes these certificates. They only
    // flag a pairing for review and never reject it.
    static ImmutableList<String> reviewFlags(final Certificate[] chain, final long responseMs) {
        final ImmutableList.Builder<String> flags = ImmutableList.builder();
        if (responseMs < FAST_RESPONSE_MS) {
            flags.add("fast-response");
        }
        try {
            final X509Certificate leaf = (X509Certificate) chain[0];
            final X509Certificate attestKey = (X509Certificate) chain[1];
            final X509Certificate root = (X509Certificate) chain[2];
            for (final X509Certificate c : new X509Certificate[]{leaf, attestKey, root}) {
                if (c.getVersion() != 3 || !ECDSA_SHA256_OID.equals(c.getSigAlgOID())) {
                    flags.add("certificate-format");
                    break;
                }
            }
            if (!Arrays.equals(leaf.getIssuerX500Principal().getEncoded(),
                    attestKey.getSubjectX500Principal().getEncoded())
                    || !Arrays.equals(attestKey.getIssuerX500Principal().getEncoded(),
                    root.getSubjectX500Principal().getEncoded())
                    || !Arrays.equals(root.getIssuerX500Principal().getEncoded(),
                    root.getSubjectX500Principal().getEncoded())) {
                flags.add("issuer-names");
            }
            if (!leaf.getNotBefore().equals(attestKey.getNotBefore())
                    || !leaf.getNotAfter().equals(attestKey.getNotAfter())
                    || !attestKey.getNotBefore().equals(root.getNotBefore())
                    || !attestKey.getNotAfter().equals(root.getNotAfter())) {
                flags.add("validity");
            }
            if (!extensions(leaf).equals(Set.of(KEY_DESCRIPTION_OID, KEY_USAGE_OID))
                    || !extensions(attestKey).equals(Set.of(KEY_DESCRIPTION_OID, KEY_USAGE_OID))
                    || !keyUsage(leaf, 0) || keyUsage(leaf, 5) || !keyUsage(attestKey, 5)) {
                flags.add("extensions");
            }
            if (!isDer(leaf) || !isDer(attestKey)) {
                flags.add("attestation-encoding");
            }
        } catch (final ClassCastException | IOException | CertificateParsingException e) {
            flags.add("certificate-format");
        }
        return flags.build();
    }

    private static Set<String> extensions(final X509Certificate certificate) {
        final java.util.HashSet<String> oids = new java.util.HashSet<>();
        if (certificate.getCriticalExtensionOIDs() != null) {
            oids.addAll(certificate.getCriticalExtensionOIDs());
        }
        if (certificate.getNonCriticalExtensionOIDs() != null) {
            oids.addAll(certificate.getNonCriticalExtensionOIDs());
        }
        return oids;
    }

    private static boolean keyUsage(final X509Certificate certificate, final int bit) {
        final boolean[] usage = certificate.getKeyUsage();
        return usage != null && usage.length > bit && usage[bit];
    }

    // The attestation extension must be canonical DER, as KeyMint produces it.
    private static boolean isDer(final X509Certificate certificate)
            throws IOException, CertificateParsingException {
        final byte[] wrapped = certificate.getExtensionValue(KEY_DESCRIPTION_OID);
        if (wrapped == null) {
            throw new CertificateParsingException("missing key description");
        }
        final byte[] octets = org.bouncycastle.asn1.ASN1OctetString.getInstance(wrapped).getOctets();
        return Arrays.equals(octets, ASN1Primitive.fromByteArray(octets).getEncoded("DER"));
    }

}
