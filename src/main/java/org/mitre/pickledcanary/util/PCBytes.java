package org.mitre.pickledcanary.util;

import java.util.ArrayList;
import java.util.List;

public class PCBytes {
    /**
     * Get a list of integers from a byte array.
     *
     * <p>
     * Bytes are interpreted as UNSIGNED integers.
     *
     * @param input
     * @return
     */
    public static List<Integer> integerList(byte[] input) {
        List<Integer> out = new ArrayList<>(input.length);
        for (byte b : input) {
            out.add(java.lang.Byte.toUnsignedInt(b));
        }

        return out;
    }
}
