// Copyright (C) 2024 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Arrays;
import java.util.stream.Collectors;

import org.json.JSONString;
import org.mitre.pickledcanary.util.PCBytes;

/**
 * A thin wrapper around a byte[] which allows the byte[] to be used as a key in a HashSet.
 */
final record ByteArrayWrapper(byte[] data) implements JSONString, Comparable<ByteArrayWrapper> {
	@Override
	public boolean equals(Object other) {
		if (other instanceof ByteArrayWrapper) {
			return Arrays.equals(data, ((ByteArrayWrapper) other).data);
		}
		else if (other instanceof byte[]) {
			return Arrays.equals(data, (byte[]) other);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(data);
	}

	public String toJSONString() {
		return "[" + PCBytes.integerList(data)
				.stream()
				.map(Object::toString)
				.collect(Collectors.joining(",")) +
			"]";
	}

	@Override
	public int compareTo(ByteArrayWrapper a) {
		int out = this.data.length - a.data.length;
		if (out != 0) {
			return out;
		}

		for (int i = 0; i < this.data.length; i++) {
			out = java.lang.Byte.toUnsignedInt(this.data[i]) -
				java.lang.Byte.toUnsignedInt(a.data[i]);
			if (out != 0) {
				return out;
			}
		}
		return out;
	}

	public String toString() {
		return toJSONString();
	}
}
