package app.attestation.server;

import app.attestation.server.attestation.ParsedAttestationRecord;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import jakarta.json.JsonArray;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.regex.Pattern;

// Devices without a manufacturer-rooted attestation chain (trust profile 2) and the keys trusted
// for them, kept as data so device specifics stay out of the verification code.
final class TrustConfig {
    static final String FORMAT = "diamaneos-attestation-trust";
    // Test deployments can point this at another file. Production uses the bundled resource.
    static final String PATH_PROPERTY = "diamaneos.trust";
    private static final Pattern SHA256_HEX = Pattern.compile("[0-9A-F]{64}");

    record Device(String id, String name, String osName, String verifiedBootKey, int securityLevel) {}

    final String auditorReleaseSigner;
    final ImmutableMap<String, PublicKey> releaseListSigners;
    final ImmutableList<Device> devices;

    private TrustConfig(final String auditorReleaseSigner,
            final ImmutableMap<String, PublicKey> releaseListSigners, final ImmutableList<Device> devices) {
        this.auditorReleaseSigner = auditorReleaseSigner;
        this.releaseListSigners = releaseListSigners;
        this.devices = devices;
    }

    private static TrustConfig instance;

    static synchronized TrustConfig get() throws GeneralSecurityException, IOException {
        if (instance == null) {
            final String path = System.getProperty(PATH_PROPERTY);
            if (path != null) {
                instance = parse(Files.readAllBytes(Path.of(path)));
            } else {
                try (final InputStream stream = TrustConfig.class.getResourceAsStream("diamaneos-trust.json")) {
                    instance = parse(stream.readAllBytes());
                }
            }
        }
        return instance;
    }

    static TrustConfig parse(final byte[] json) throws GeneralSecurityException {
        try (final JsonReader reader = Json.createReader(new ByteArrayInputStream(json))) {
            final JsonObject root = reader.readObject();
            if (!FORMAT.equals(root.getString("format")) || root.getJsonNumber("version").intValueExact() != 1) {
                throw new GeneralSecurityException("unsupported trust configuration");
            }
            final String signer = root.getString("auditorReleaseSigner");
            if (!signer.isEmpty() && !SHA256_HEX.matcher(signer).matches()) {
                throw new GeneralSecurityException("invalid Auditor signer digest");
            }
            final ImmutableMap.Builder<String, PublicKey> signers = ImmutableMap.builder();
            for (final String encoded : root.getJsonArray("releaseListSigners").getValuesAs(
                    jakarta.json.JsonString::getString)) {
                final PublicKey key = decodeP256(encoded);
                signers.put(keyId(key), key);
            }
            final ImmutableList.Builder<Device> devices = ImmutableList.builder();
            final JsonArray deviceArray = root.getJsonArray("devices");
            for (final JsonObject device : deviceArray.getValuesAs(JsonObject.class)) {
                final String verifiedBootKey = device.getString("verifiedBootKey");
                if (!SHA256_HEX.matcher(verifiedBootKey).matches()) {
                    throw new GeneralSecurityException("invalid verified boot key");
                }
                devices.add(new Device(device.getString("id"), device.getString("name"),
                        device.getString("osName"), verifiedBootKey,
                        securityLevel(device.getString("securityLevel"))));
            }
            return new TrustConfig(signer, signers.buildOrThrow(), devices.build());
        } catch (final JsonException | ClassCastException | NullPointerException | ArithmeticException |
                IllegalArgumentException e) {
            throw new GeneralSecurityException("invalid trust configuration", e);
        }
    }

    List<Device> devicesFor(final String verifiedBootKey, final int securityLevel) {
        return devices.stream()
                .filter(d -> d.verifiedBootKey.equals(verifiedBootKey) && d.securityLevel == securityLevel)
                .collect(ImmutableList.toImmutableList());
    }

    Device device(final String id) {
        return devices.stream().filter(d -> d.id.equals(id)).findFirst().orElse(null);
    }

    static String keyId(final PublicKey key) {
        return BaseEncoding.base16().encode(Hashing.sha256().hashBytes(key.getEncoded()).asBytes());
    }

    private static PublicKey decodeP256(final String base64) throws GeneralSecurityException {
        final PublicKey key = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(BaseEncoding.base64().decode(base64)));
        final AlgorithmParameters p256 = AlgorithmParameters.getInstance("EC");
        p256.init(new ECGenParameterSpec("secp256r1"));
        final ECParameterSpec expected = p256.getParameterSpec(ECParameterSpec.class);
        if (!(key instanceof ECPublicKey ec)
                || !ec.getParams().getCurve().equals(expected.getCurve())
                || !ec.getParams().getOrder().equals(expected.getOrder())) {
            throw new GeneralSecurityException("release list signer must be a P-256 key");
        }
        return key;
    }

    private static int securityLevel(final String name) throws GeneralSecurityException {
        return switch (name) {
            case "TRUSTED_ENVIRONMENT" -> ParsedAttestationRecord.securityLevelToInt(
                    ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT);
            case "STRONG_BOX" -> ParsedAttestationRecord.securityLevelToInt(
                    ParsedAttestationRecord.SecurityLevel.STRONG_BOX);
            default -> throw new GeneralSecurityException("invalid security level: " + name);
        };
    }
}
