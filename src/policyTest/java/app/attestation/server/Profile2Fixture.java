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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
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

// Software-made reports shaped like a profile 2 Auditee's. They carry no hardware trust.
final class Profile2Fixture {
    static final byte[] AVB_KEY = sha256("test AVB key");
    static final byte[] AUDITOR_SIGNER = sha256("test Auditor signer");
    static final KeyPair LIST_SIGNER = keyPair();

    final KeyPair root = keyPair();
    final KeyPair attest = keyPair();
    final KeyPair persistent = keyPair();
    // null for an initial pairing, else the fresh key of a later check
    KeyPair fresh;
    Certificate persistentCertificate;

    byte[] challenge;
    byte[] attestChallenge;
    byte[] bootKey = AVB_KEY;
    byte[] bootHash = sha256("release 1");
    boolean locked = true;
    RootOfTrust.VerifiedBootState state = RootOfTrust.VerifiedBootState.SELF_SIGNED;
    int osVersion = 170000;
    int osPatchLevel = 202610;
    int vendorPatchLevel = 20261005;
    int bootPatchLevel = 20261005;
    int attestationVersion = 300;
    int keyMintVersion = 300;
    String packageName = "de.diamaneos.auditor";
    long appVersion = 9202;
    byte[] signer = AUDITOR_SIGNER;
    private Certificate attestCertificate;
    private Certificate rootCertificate;

    // Serialized Auditor message for the current state, signed with the persistent key.
    byte[] message() throws Exception {
        final X500Name name = new X500Name("CN=Android Keystore Key");
        final ParsedAttestationRecord.SecurityLevel tee = ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT;
        if (attestCertificate == null) {
            rootCertificate = certificate(root, name, root, null, KeyUsage.keyCertSign);
            attestCertificate = certificate(attest, name, root,
                    extension(Set.of(AuthorizationList.OperationPurpose.ATTEST_KEY),
                            attestChallenge != null ? attestChallenge : challenge, tee), KeyUsage.keyCertSign);
        }
        final KeyPair leafKey = fresh != null ? fresh : persistent;
        final Certificate leaf = certificate(leafKey, name, attest,
                extension(Set.of(AuthorizationList.OperationPurpose.SIGN, AuthorizationList.OperationPurpose.VERIFY),
                        challenge, tee), KeyUsage.digitalSignature);
        if (fresh == null) {
            persistentCertificate = leaf;
        }
        final Certificate[] chain = {leaf, attestCertificate, rootCertificate};
        final byte[] compressed = AttestationProtocol.encodeChain(AttestationProtocol.DEFLATE_DICTIONARY_5, chain);
        final ByteBuffer buffer = ByteBuffer.allocate(AttestationProtocol.MAX_MESSAGE_SIZE);
        buffer.put(AttestationProtocol.PROTOCOL_VERSION);
        buffer.putShort((short) compressed.length);
        buffer.put(compressed);
        buffer.put(MessageDigest.getInstance("SHA-256").digest(persistentCertificate.getEncoded()));
        buffer.putInt(1);
        buffer.putInt(-1);
        buffer.put((byte) -1);
        buffer.put((byte) -1);
        buffer.put((byte) -1);
        final Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(persistent.getPrivate());
        signature.update(buffer.array(), 0, buffer.position());
        buffer.put(signature.sign());
        final byte[] message = new byte[buffer.position()];
        buffer.flip().get(message);
        return message;
    }

    // Switches to a later check: same pinned keys, a fresh key and a new challenge.
    void nextCheck(final byte[] newChallenge) {
        attestChallenge = attestChallenge != null ? attestChallenge : challenge;
        challenge = newChallenge;
        fresh = keyPair();
    }

    private DERSequence extension(final Set<AuthorizationList.OperationPurpose> purposes,
            final byte[] keyChallenge, final ParsedAttestationRecord.SecurityLevel level) {
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

    private static Certificate certificate(final KeyPair subject, final X500Name name, final KeyPair signer,
            final DERSequence keyDescription, final int keyUsage) throws Exception {
        final AlgorithmIdentifier ecdsa = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));
        final V3TBSCertificateGenerator generator = new V3TBSCertificateGenerator();
        generator.setSerialNumber(new ASN1Integer(1));
        generator.setSignature(ecdsa);
        generator.setIssuer(name);
        generator.setSubject(name);
        generator.setStartDate(new Time(new Date(0)));
        generator.setEndDate(new Time(new Date(2461449600000L)));
        generator.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(subject.getPublic().getEncoded()));
        final List<Extension> extensions = new ArrayList<>();
        extensions.add(new Extension(Extension.keyUsage, true, new KeyUsage(keyUsage).getEncoded()));
        if (keyDescription != null) {
            extensions.add(new Extension(new ASN1ObjectIdentifier(Profile2.KEY_DESCRIPTION_OID), false,
                    new DEROctetString(keyDescription.getEncoded())));
        }
        generator.setExtensions(new Extensions(extensions.toArray(new Extension[0])));
        final TBSCertificate tbs = generator.generateTBSCertificate();
        final Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(signer.getPrivate());
        signature.update(tbs.getEncoded("DER"));
        final byte[] der = new DERSequence(new ASN1Encodable[]{tbs, ecdsa, new DERBitString(signature.sign())})
                .getEncoded("DER");
        return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    static TrustConfig trust() throws Exception {
        final String json = Json.createObjectBuilder()
                .add("format", TrustConfig.FORMAT)
                .add("version", 1)
                .add("auditorReleaseSigner", BaseEncoding.base16().encode(AUDITOR_SIGNER))
                .add("releaseListSigners", Json.createArrayBuilder()
                        .add(Base64.getEncoder().encodeToString(LIST_SIGNER.getPublic().getEncoded())))
                .add("devices", Json.createArrayBuilder().add(Json.createObjectBuilder()
                        .add("id", "FP6")
                        .add("name", "Fairphone 6")
                        .add("osName", "DiamaneOS")
                        .add("verifiedBootKey", BaseEncoding.base16().encode(AVB_KEY))
                        .add("securityLevel", "TRUSTED_ENVIRONMENT")))
                .build().toString();
        return TrustConfig.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    static JsonObject release(final byte[] bootHash, final int osPatchLevel) {
        return Json.createObjectBuilder()
                .add("build", "2026101700")
                .add("verifiedBootHash", BaseEncoding.base16().encode(bootHash))
                .add("osVersion", 170000)
                .add("osPatchLevel", osPatchLevel)
                .add("vendorPatchLevel", 20261005)
                .add("bootPatchLevel", 20261005)
                .add("attestationVersion", 300)
                .add("keyMintVersion", 300)
                .build();
    }

    static byte[] releaseList(final KeyPair signerKey, final long sequence, final JsonObject... releases)
            throws Exception {
        final JsonArrayBuilder array = Json.createArrayBuilder();
        for (final JsonObject release : releases) {
            array.add(release);
        }
        final byte[] payload = Json.createObjectBuilder()
                .add("format", ReleaseList.PAYLOAD_FORMAT)
                .add("version", 1)
                .add("sequence", sequence)
                .add("issued", "2026-10-17T00:00:00Z")
                .add("devices", Json.createArrayBuilder().add(Json.createObjectBuilder()
                        .add("id", "FP6")
                        .add("verifiedBootKey", BaseEncoding.base16().encode(AVB_KEY))
                        .add("releases", array)))
                .build().toString().getBytes(StandardCharsets.UTF_8);
        final Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(signerKey.getPrivate());
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

    static KeyPair keyPair() {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (final Exception e) {
            throw new AssertionError(e);
        }
    }

    static byte[] sha256(final String value) {
        return Hashing.sha256().hashString(value, StandardCharsets.UTF_8).asBytes();
    }
}
