package app.attestation.server;

import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Map;
import java.util.regex.Pattern;

// Signed list of the values each official release reports through attestation. The release
// pipeline publishes it, so trust profile 2 needs no code change per OS release.
final class ReleaseList {
    static final String FORMAT = "diamaneos-attestation-releases";
    static final String PAYLOAD_FORMAT = "diamaneos-attestation-releases-payload";
    static final int MAX_SIZE = 1024 * 1024;
    private static final String ALGORITHM = "ECDSA_P256_SHA256";
    private static final Pattern SHA256_HEX = Pattern.compile("[0-9A-F]{64}");

    record Release(String build, String verifiedBootHash, int osVersion, int osPatchLevel,
            int vendorPatchLevel, int bootPatchLevel, int attestationVersion, int keyMintVersion) {}

    record DeviceReleases(String id, String verifiedBootKey, ImmutableList<Release> releases) {}

    final long sequence;
    final ImmutableList<DeviceReleases> devices;

    private ReleaseList(final long sequence, final ImmutableList<DeviceReleases> devices) {
        this.sequence = sequence;
        this.devices = devices;
    }

    // Returns the release with this boot hash for the device, or null.
    Release find(final String deviceId, final String verifiedBootKey, final String verifiedBootHash) {
        for (final DeviceReleases device : devices) {
            if (device.id.equals(deviceId) && device.verifiedBootKey.equals(verifiedBootKey)) {
                for (final Release release : device.releases) {
                    if (release.verifiedBootHash.equals(verifiedBootHash)) {
                        return release;
                    }
                }
            }
        }
        return null;
    }

    static ReleaseList parse(final byte[] envelope, final Map<String, PublicKey> signers)
            throws GeneralSecurityException {
        if (envelope.length > MAX_SIZE) {
            throw new GeneralSecurityException("release list too large");
        }
        try {
            final JsonObject root = read(envelope);
            if (!FORMAT.equals(root.getString("format")) || root.getJsonNumber("version").intValueExact() != 1) {
                throw new GeneralSecurityException("unsupported release list");
            }
            final byte[] payload = BaseEncoding.base64().decode(root.getString("payload"));
            verifySignature(payload, root, signers);
            return parsePayload(read(payload));
        } catch (final JsonException | ClassCastException | NullPointerException | ArithmeticException |
                IllegalArgumentException e) {
            throw new GeneralSecurityException("invalid release list", e);
        }
    }

    private static JsonObject read(final byte[] json) {
        try (final JsonReader reader = Json.createReader(new ByteArrayInputStream(json))) {
            return reader.readObject();
        }
    }

    private static void verifySignature(final byte[] payload, final JsonObject root,
            final Map<String, PublicKey> signers) throws GeneralSecurityException {
        for (final JsonObject entry : root.getJsonArray("signatures").getValuesAs(JsonObject.class)) {
            final PublicKey key = signers.get(entry.getString("keyId"));
            if (key == null || !ALGORITHM.equals(entry.getString("algorithm"))) {
                continue;
            }
            final Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(key);
            signature.update(payload);
            if (signature.verify(BaseEncoding.base64().decode(entry.getString("signature")))) {
                return;
            }
        }
        throw new GeneralSecurityException("release list has no valid trusted signature");
    }

    private static ReleaseList parsePayload(final JsonObject payload) throws GeneralSecurityException {
        if (!PAYLOAD_FORMAT.equals(payload.getString("format"))
                || payload.getJsonNumber("version").intValueExact() != 1) {
            throw new GeneralSecurityException("unsupported release list payload");
        }
        final long sequence = payload.getJsonNumber("sequence").longValueExact();
        if (sequence < 1) {
            throw new GeneralSecurityException("invalid release list sequence");
        }
        final ImmutableList.Builder<DeviceReleases> devices = ImmutableList.builder();
        for (final JsonObject device : payload.getJsonArray("devices").getValuesAs(JsonObject.class)) {
            final ImmutableList.Builder<Release> releases = ImmutableList.builder();
            for (final JsonObject r : device.getJsonArray("releases").getValuesAs(JsonObject.class)) {
                releases.add(new Release(r.getString("build"), sha256Hex(r, "verifiedBootHash"),
                        positive(r, "osVersion"), positive(r, "osPatchLevel"),
                        positive(r, "vendorPatchLevel"), positive(r, "bootPatchLevel"),
                        positive(r, "attestationVersion"), positive(r, "keyMintVersion")));
            }
            devices.add(new DeviceReleases(device.getString("id"), sha256Hex(device, "verifiedBootKey"),
                    releases.build()));
        }
        return new ReleaseList(sequence, devices.build());
    }

    private static String sha256Hex(final JsonObject object, final String name)
            throws GeneralSecurityException {
        final String value = object.getString(name);
        if (!SHA256_HEX.matcher(value).matches()) {
            throw new GeneralSecurityException("invalid " + name);
        }
        return value;
    }

    private static int positive(final JsonObject object, final String name) throws GeneralSecurityException {
        final int value = object.getJsonNumber(name).intValueExact();
        if (value <= 0) {
            throw new GeneralSecurityException("invalid " + name);
        }
        return value;
    }
}
