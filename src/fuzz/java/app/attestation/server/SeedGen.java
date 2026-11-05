package app.attestation.server;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;

// Writes a target's seeds, made from the fixture, into <fuzz.dir>/seeds.
public final class SeedGen {
    public static void main(final String[] args) throws Exception {
        @SuppressWarnings("unchecked")
        final List<byte[]> seeds = (List<byte[]>) Class.forName("app.attestation.server." + args[0])
                .getMethod("seeds").invoke(null);
        final Path dir = Path.of(System.getProperty("fuzz.dir"), "seeds");
        Files.createDirectories(dir);
        for (final byte[] seed : seeds) {
            final byte[] digest = java.security.MessageDigest.getInstance("SHA-1").digest(seed);
            Files.write(dir.resolve(HexFormat.of().formatHex(digest)), seed);
        }
        System.out.println(args[0] + ": " + seeds.size() + " seeds");
        System.exit(0);
    }
}
