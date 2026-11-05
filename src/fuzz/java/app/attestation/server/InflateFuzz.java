package app.attestation.server;

import com.google.common.primitives.Bytes;

import java.io.ByteArrayOutputStream;
import java.nio.BufferUnderflowException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

// The compressed certificate chain and its length fields.
//
// Input: byte 0 picks the dictionary (even: version 7, odd: version 6), the rest is the compressed
// chain as the message carries it.
//
// Invariants: inflating stops at the chain limit, so a zip bomb is refused without growing memory
// or time with the expanded size. Only the exceptions the verify handler answers with 400 escape. A
// decoded chain fits the limit when encoded again, and every certificate in it is complete.
public final class InflateFuzz {
    private static final int MAX_ENCODED_CHAIN_LENGTH = 5000;
    private static final List<byte[]> seeds = new ArrayList<>();

    public static void fuzzerInitialize() throws Exception {
        FuzzFixture.installTestRoot();
    }

    public static List<byte[]> seeds() throws Exception {
        fuzzerInitialize();
        for (final boolean profile1 : new boolean[]{true, false}) {
            final Certificate[] chain = new FuzzFixture(profile1 ? "inflate p1" : "inflate p2", profile1).chain();
            seeds.add(Bytes.concat(new byte[]{0}, AttestationProtocol.encodeChain(
                    AttestationProtocol.DEFLATE_DICTIONARY_5, chain)));
            seeds.add(Bytes.concat(new byte[]{1}, AttestationProtocol.encodeChain(
                    AttestationProtocol.DEFLATE_DICTIONARY_4, chain)));
        }
        // a zip bomb: 16 MiB of zeros, and a length field promising more than is there
        seeds.add(Bytes.concat(new byte[]{0}, deflate(new byte[16 * 1024 * 1024])));
        seeds.add(Bytes.concat(new byte[]{0}, deflate(new byte[]{0x7f, (byte) 0xff, 1, 2, 3})));
        seeds.add(Bytes.concat(new byte[]{0}, deflate(new byte[]{(byte) 0x80, 0})));
        return seeds;
    }

    private static byte[] deflate(final byte[] data) throws Exception {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true)) {
            deflater.setDictionary(AttestationProtocol.DEFLATE_DICTIONARY_5);
            final DeflaterOutputStream stream = new DeflaterOutputStream(out, deflater);
            stream.write(data);
            stream.finish();
        }
        return out.toByteArray();
    }

    public static void fuzzerTestOneInput(final byte[] data) throws Exception {
        if (data.length < 1) {
            return;
        }
        final byte[] dictionary = (data[0] & 1) == 0 ? AttestationProtocol.DEFLATE_DICTIONARY_5
                : AttestationProtocol.DEFLATE_DICTIONARY_4;
        final byte[] compressed = Arrays.copyOfRange(data, 1, data.length);
        final long start = System.nanoTime();
        final Certificate[] chain;
        try {
            chain = AttestationProtocol.decodeChain(dictionary, compressed);
        } catch (final DataFormatException | GeneralSecurityException | BufferUnderflowException |
                NegativeArraySizeException e) {
            return;
        } finally {
            if (System.nanoTime() - start > 2_000_000_000L) {
                throw new AssertionError("inflating took over two seconds");
            }
        }
        int length = 0;
        for (final Certificate certificate : chain) {
            length += 2 + certificate.getEncoded().length;
        }
        if (length > MAX_ENCODED_CHAIN_LENGTH) {
            throw new AssertionError("decoded chain over the limit: " + length);
        }
        // the encoded chain round trips
        final Certificate[] again = AttestationProtocol.decodeChain(dictionary,
                AttestationProtocol.encodeChain(dictionary, chain));
        if (again.length != chain.length) {
            throw new AssertionError("chain does not round trip");
        }
    }
}
