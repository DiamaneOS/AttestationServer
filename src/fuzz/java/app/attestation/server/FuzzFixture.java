package app.attestation.server;

import app.attestation.server.attestation.AttestationApplicationId;
import app.attestation.server.attestation.AuthorizationList;
import app.attestation.server.attestation.ParsedAttestationRecord;
import app.attestation.server.attestation.RootOfTrust;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

// Reports made in software from throwaway test keys. Every key and signature is derived from a
// label, so seeds written by one run still verify in the next. Nothing here is a real device.
final class FuzzFixture {
    static final KeyPair TEST_ROOT = keyPair("fuzz test root");
    static final KeyPair TEST_LIST_SIGNER = keyPair("fuzz test release list signer");
    static final byte[] TEST_AVB_KEY = sha256("fuzz test AVB key");
    static final byte[] TEST_AUDITOR_SIGNER = sha256("fuzz test Auditor signer");
    static final byte[] RELEASE_1 = sha256("fuzz test release 1");
    static final byte[] RELEASE_2 = sha256("fuzz test release 2");
    private static final Certificate TEST_ROOT_CERTIFICATE;

    static {
        try {
            TEST_ROOT_CERTIFICATE = certificate(TEST_ROOT, "CN=Fuzz Test Root", TEST_ROOT, "CN=Fuzz Test Root",
                    null, KeyUsage.keyCertSign, "root");
        } catch (final Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    final String label;
    final boolean profile1;
    final KeyPair root;
    final KeyPair intermediate;
    final KeyPair attest;
    final KeyPair persistent;
    KeyPair fresh;
    Certificate persistentCertificate;
    private Certificate attestCertificate;
    private Certificate intermediateCertificate;
    private Certificate rootCertificate;

    byte[] challenge;
    byte[] attestChallenge;
    byte[] bootKey;
    byte[] bootHash = RELEASE_1;
    boolean locked = true;
    RootOfTrust.VerifiedBootState state;
    ParsedAttestationRecord.SecurityLevel level;
    int osVersion = 170000;
    int osPatchLevel = 202610;
    int vendorPatchLevel = 20261005;
    int bootPatchLevel = 20261005;
    int attestationVersion = 300;
    int keyMintVersion = 300;
    String packageName = "de.diamaneos.auditor";
    long appVersion = 9202;
    byte[] signer = TEST_AUDITOR_SIGNER;
    int osEnforcedFlags = 1;
    int checks;

    FuzzFixture(final String label, final boolean profile1) {
        this.label = label;
        this.profile1 = profile1;
        root = profile1 ? TEST_ROOT : keyPair(label + " local root");
        intermediate = keyPair(label + " intermediate");
        attest = keyPair(label + " attest");
        persistent = keyPair(label + " persistent");
        bootKey = profile1 ? BaseEncoding.base16().decode(profile1BootKey()) : TEST_AVB_KEY;
        state = profile1 ? RootOfTrust.VerifiedBootState.VERIFIED : RootOfTrust.VerifiedBootState.SELF_SIGNED;
        level = profile1 ? ParsedAttestationRecord.SecurityLevel.STRONG_BOX
                : ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT;
        challenge = token(label + " challenge 0");
    }

    // A verified boot key from the profile 1 allowlist (a StrongBox phone), used only as a lookup value.
    static String profile1BootKey() {
        return AttestationProtocol.fingerprintsStrongBoxStock.keySet().asList().get(8);
    }

    // Writes the test root where the classpath finds it before the bundled first root. Must run
    // before AttestationProtocol is loaded.
    static void installTestRoot() throws Exception {
        final String dir = System.getProperty("fuzz.dir");
        if (dir == null) {
            throw new IllegalStateException("fuzz.dir not set");
        }
        final Path path = Path.of(dir, "roots", "app", "attestation", "server", "google_root_0.der");
        Files.createDirectories(path.getParent());
        Files.write(path, TEST_ROOT_CERTIFICATE.getEncoded());
    }

    static byte[] testRootEncoded() throws Exception {
        return TEST_ROOT_CERTIFICATE.getEncoded();
    }

    Certificate[] chain() throws Exception {
        final String name = "CN=Android Keystore Key";
        if (attestCertificate == null) {
            if (profile1) {
                rootCertificate = TEST_ROOT_CERTIFICATE;
                intermediateCertificate = certificate(intermediate, "CN=Fuzz Test Intermediate", root,
                        "CN=Fuzz Test Root", null, KeyUsage.keyCertSign, label + " intermediate");
                attestCertificate = certificate(attest, name, intermediate, "CN=Fuzz Test Intermediate",
                        extension(Set.of(AuthorizationList.OperationPurpose.ATTEST_KEY),
                                attestChallenge != null ? attestChallenge : challenge), KeyUsage.keyCertSign,
                        label + " attest");
            } else {
                rootCertificate = certificate(root, name, root, name, null, KeyUsage.keyCertSign, label + " root");
                attestCertificate = certificate(attest, name, root, name,
                        extension(Set.of(AuthorizationList.OperationPurpose.ATTEST_KEY),
                                attestChallenge != null ? attestChallenge : challenge), KeyUsage.keyCertSign,
                        label + " attest");
            }
        }
        final KeyPair leafKey = fresh != null ? fresh : persistent;
        final Certificate leaf = certificate(leafKey, name, attest, name,
                extension(Set.of(AuthorizationList.OperationPurpose.SIGN, AuthorizationList.OperationPurpose.VERIFY),
                        challenge), KeyUsage.digitalSignature, label + " leaf " + checks);
        if (fresh == null) {
            persistentCertificate = leaf;
        }
        return profile1 ? new Certificate[]{leaf, attestCertificate, intermediateCertificate, rootCertificate}
                : new Certificate[]{leaf, attestCertificate, rootCertificate};
    }

    // Serialized Auditor message for the current state, signed with the persistent key.
    byte[] message() throws Exception {
        final Certificate[] chain = chain();
        final byte[] compressed = AttestationProtocol.encodeChain(AttestationProtocol.DEFLATE_DICTIONARY_5, chain);
        final ByteBuffer buffer = ByteBuffer.allocate(AttestationProtocol.MAX_MESSAGE_SIZE);
        buffer.put(AttestationProtocol.PROTOCOL_VERSION);
        buffer.putShort((short) compressed.length);
        buffer.put(compressed);
        buffer.put(MessageDigest.getInstance("SHA-256").digest(persistentCertificate.getEncoded()));
        buffer.putInt(osEnforcedFlags);
        buffer.putInt(-1);
        buffer.put((byte) -1);
        buffer.put((byte) -1);
        buffer.put((byte) -1);
        final Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(persistent.getPrivate(), random(label + " message " + checks));
        signature.update(buffer.array(), 0, buffer.position());
        buffer.put(signature.sign());
        final byte[] message = new byte[buffer.position()];
        buffer.flip().get(message);
        return message;
    }

    // Switches to a later check: same pinned keys, a fresh key and a new challenge.
    void nextCheck() {
        checks++;
        attestChallenge = attestChallenge != null ? attestChallenge : challenge;
        challenge = token(label + " challenge " + checks);
        fresh = keyPair(label + " fresh " + checks);
    }

    byte[] fingerprint() throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(persistentCertificate.getEncoded());
    }

    private DERSequence extension(final Set<AuthorizationList.OperationPurpose> purposes, final byte[] keyChallenge) {
        final AuthorizationList tee = AuthorizationList.builder()
                .setPurpose(purposes)
                .setAlgorithm(AuthorizationList.Algorithm.EC)
                .setKeySize(256)
                .setEcCurve(AuthorizationList.EcCurve.P_256)
                .setDigest(Set.of(AuthorizationList.DigestMode.SHA_2_256))
                .setOrigin(AuthorizationList.KeyOrigin.GENERATED)
                .setRootOfTrust(RootOfTrust.create(bootKey, locked, state, Optional.of(bootHash)))
                .setOsVersion(osVersion)
                .setOsPatchLevel(osPatchLevel)
                .setVendorPatchLevel(vendorPatchLevel)
                .setBootPatchLevel(bootPatchLevel)
                .build();
        final AuthorizationList software = AuthorizationList.builder()
                .setAttestationApplicationId(new AttestationApplicationId(
                        List.of(new AttestationApplicationId.AttestationPackageInfo(packageName, appVersion)),
                        List.of(signer)))
                .build();
        return new DERSequence(ParsedAttestationRecord.create(attestationVersion, level, keyMintVersion, level,
                keyChallenge, new byte[0], software, tee, persistent.getPublic()).toAsn1Sequence().toArray());
    }

    static Certificate certificate(final KeyPair subject, final String subjectName, final KeyPair signer,
            final String issuerName, final DERSequence keyDescription, final int keyUsage, final String label)
            throws Exception {
        return certificateRaw(subject, subjectName, signer, issuerName,
                keyDescription == null ? null : keyDescription.getEncoded(), keyUsage, label);
    }

    // The leaf (position 0) or attest key certificate (1) of the current chain, with the given
    // attestation extension contents, signed by its real issuer.
    Certificate resigned(final int position, final byte[] keyDescription) throws Exception {
        final String name = "CN=Android Keystore Key";
        if (position == 0) {
            return certificateRaw(fresh != null ? fresh : persistent, name, attest, name, keyDescription,
                    KeyUsage.digitalSignature, label + " resigned leaf");
        }
        return certificateRaw(attest, name, profile1 ? intermediate : root,
                profile1 ? "CN=Fuzz Test Intermediate" : name, keyDescription, KeyUsage.keyCertSign,
                label + " resigned attest");
    }

    static Certificate certificateRaw(final KeyPair subject, final String subjectName, final KeyPair signer,
            final String issuerName, final byte[] keyDescription, final int keyUsage, final String label)
            throws Exception {
        final AlgorithmIdentifier ecdsa = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));
        final V3TBSCertificateGenerator generator = new V3TBSCertificateGenerator();
        generator.setSerialNumber(new ASN1Integer(1));
        generator.setSignature(ecdsa);
        generator.setIssuer(new X500Name(issuerName));
        generator.setSubject(new X500Name(subjectName));
        generator.setStartDate(new Time(new Date(0)));
        generator.setEndDate(new Time(new Date(2461449600000L)));
        generator.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(subject.getPublic().getEncoded()));
        final List<Extension> extensions = new ArrayList<>();
        extensions.add(new Extension(Extension.keyUsage, true, new KeyUsage(keyUsage).getEncoded()));
        if (keyDescription != null) {
            extensions.add(new Extension(new ASN1ObjectIdentifier(Profile2.KEY_DESCRIPTION_OID), false,
                    new DEROctetString(keyDescription)));
        }
        generator.setExtensions(new Extensions(extensions.toArray(new Extension[0])));
        final TBSCertificate tbs = generator.generateTBSCertificate();
        final Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(signer.getPrivate(), random(label + " certificate"));
        signature.update(tbs.getEncoded("DER"));
        final byte[] der = new DERSequence(new ASN1Encodable[]{tbs, ecdsa, new DERBitString(signature.sign())})
                .getEncoded("DER");
        return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    static TrustConfig trust() throws Exception {
        final String json = Json.createObjectBuilder()
                .add("format", TrustConfig.FORMAT)
                .add("version", 1)
                .add("auditorReleaseSigner", BaseEncoding.base16().encode(TEST_AUDITOR_SIGNER))
                .add("releaseListSigners", Json.createArrayBuilder()
                        .add(Base64.getEncoder().encodeToString(TEST_LIST_SIGNER.getPublic().getEncoded())))
                .add("devices", Json.createArrayBuilder().add(Json.createObjectBuilder()
                        .add("id", "TEST1")
                        .add("buildDevice", "test1")
                        .add("name", "Test Phone")
                        .add("osName", "Test OS")
                        .add("verifiedBootKey", BaseEncoding.base16().encode(TEST_AVB_KEY))
                        .add("securityLevel", "TRUSTED_ENVIRONMENT")))
                .build().toString();
        return TrustConfig.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    static JsonObject release(final byte[] bootHash, final int osPatchLevel) {
        return Json.createObjectBuilder()
                .add("build", "TEST." + osPatchLevel)
                .add("verifiedBootHash", BaseEncoding.base16().encode(bootHash))
                .add("osVersion", 170000)
                .add("osPatchLevel", osPatchLevel)
                .add("vendorPatchLevel", 20261005)
                .add("bootPatchLevel", 20261005)
                .add("attestationVersion", 300)
                .add("keyMintVersion", 300)
                .build();
    }

    static byte[] releasePayload(final long sequence, final JsonObject... releases) {
        final JsonArrayBuilder array = Json.createArrayBuilder();
        for (final JsonObject release : releases) {
            array.add(release);
        }
        return Json.createObjectBuilder()
                .add("format", ReleaseList.PAYLOAD_FORMAT)
                .add("version", 1)
                .add("sequence", sequence)
                .add("issued", "2026-10-17T00:00:00Z")
                .add("devices", Json.createArrayBuilder().add(Json.createObjectBuilder()
                        .add("id", "TEST1")
                        .add("verifiedBootKey", BaseEncoding.base16().encode(TEST_AVB_KEY))
                        .add("releases", array)))
                .build().toString().getBytes(StandardCharsets.UTF_8);
    }

    static byte[] releaseEnvelope(final KeyPair signerKey, final byte[] payload) throws Exception {
        final Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(signerKey.getPrivate(), random("release list " + new String(payload, StandardCharsets.UTF_8)));
        signature.update(payload);
        return Json.createObjectBuilder()
                .add("format", ReleaseList.FORMAT)
                .add("version", 1)
                .add("payload", Base64.getEncoder().encodeToString(payload))
                .add("signatures", Json.createArrayBuilder().add(Json.createObjectBuilder()
                        .add("keyId", TrustConfig.keyId(signerKey.getPublic()))
                        .add("algorithm", "ECDSA_P256_SHA256")
                        .add("signature", Base64.getEncoder().encodeToString(signature.sign()))))
                .build().toString().getBytes(StandardCharsets.UTF_8);
    }

    static ReleaseList releases() throws Exception {
        return ReleaseList.parse(releaseEnvelope(TEST_LIST_SIGNER, releasePayload(1,
                release(RELEASE_1, 202610), release(RELEASE_2, 202611))), trust().releaseListSigners);
    }

    static SecureRandom random(final String label) {
        try {
            final SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(label.getBytes(StandardCharsets.UTF_8));
            return random;
        } catch (final Exception e) {
            throw new AssertionError(e);
        }
    }

    static KeyPair keyPair(final String label) {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), random(label + " key"));
            return generator.generateKeyPair();
        } catch (final Exception e) {
            throw new AssertionError(e);
        }
    }

    static byte[] token(final String label) {
        final byte[] token = new byte[AttestationProtocol.RANDOM_TOKEN_LENGTH];
        random(label).nextBytes(token);
        return token;
    }

    static byte[] sha256(final String value) {
        return Hashing.sha256().hashString(value, StandardCharsets.UTF_8).asBytes();
    }
}
