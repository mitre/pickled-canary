
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.utils;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Objects;

/**
 * Represents a string of bits.
 */
public class BitArray {

	private final BitSet bs; // the bits
	private final int numBytes; // number of bytes in the bits being passed in (BitSet removes leading 0s)

	/**
	 * Construct an empty string of bits given a number of bytes.
	 *
	 * @param numBytes the number of bytes that this string of bits should have
	 */
	public BitArray(int numBytes) {
		bs = new BitSet();
		this.numBytes = numBytes;
	}

	/**
	 * Construct a new string of bits given a byte array.
	 *
	 * @param bits the bits
	 */
	public BitArray(byte[] bits) {
		bs = BitSet.valueOf(Utils.reverse(bits));
		numBytes = bits.length;
	}

	/**
	 * Construct a new string of bits given a list of integers.
	 *
	 * @param bits the bits
	 */
	public BitArray(List<Integer> bits) {
		byte[] b = new byte[bits.size()];
		for (int i = 0; i < bits.size(); i++) {
			b[i] = (byte) ((int) bits.get(i));
		}
		bs = BitSet.valueOf(Utils.reverse(b));
		numBytes = b.length;
	}

	/**
	 * Construct a new string of bits given a BitSet and number of bytes.
	 *
	 * @param bs       the bits
	 * @param numBytes the number of bytes that this string of bits should have
	 */
	public BitArray(BitSet bs, int numBytes) {
		this.bs = bs;
		this.numBytes = numBytes;
	}

	/**
	 * Construct a new string of bits given an existing BitArray.
	 *
	 * @param ba the bits
	 */
	public BitArray(BitArray ba) {
		this.bs = (BitSet) ba.bs.clone();
		this.numBytes = ba.numBytes;
	}

	/**
	 * Get number of bytes needed to represent bits, including all leading and
	 * trailing zeros.
	 *
	 * @return length in bytes
	 */
	public int length() {
		return numBytes;
	}

	/**
	 * Performs a bitwise AND operation between two BitArrays.
	 *
	 * @see BitSet#and(BitSet set)
	 * @param ba the BitArray that this BitArray should perform an AND with
	 * @return a new string of bits with the resulting AND operation
	 */
	public BitArray and(BitArray ba) {
		BitSet newBS = (BitSet) bs.clone();
		newBS.and(ba.bs);
		return new BitArray(newBS, length() > ba.length() ? numBytes : ba.numBytes);
	}

	/**
	 * Performs a bitwise NOT operation.
	 *
	 * @see BitSet#flip(int, int)
	 * @return a new string of bits with the resulting NOT operation
	 */
	public BitArray not() {
		BitSet newBS = (BitSet) bs.clone();
		newBS.flip(0, numBytes * 8);
		return new BitArray(newBS, numBytes);
	}

	/**
	 * Performs a bitwise OR operation between two BitArrays.
	 *
	 * @see BitSet#or(BitSet)
	 * @param ba the BitArray that this BitArray should perform an OR with
	 * @return a new string of bits with the resulting OR operation
	 */
	public BitArray or(BitArray ba) {
		BitSet newBS = (BitSet) bs.clone();
		newBS.or(ba.bs);
		return new BitArray(newBS, length() > ba.length() ? numBytes : ba.numBytes);
	}

	/**
	 * Get the bits that match a given mask.
	 *
	 * @param mask the mask that should be matched to
	 * @return new set of masked bits with the length of the BitArray set to the
	 *         smallest number of bytes needed to fit the mask
	 */
	public BitArray trimToMask(BitArray mask) {
		int start = mask.bs.nextSetBit(0);
		if (start < 0) {
			return new BitArray(mask);
		}
		int end = mask.bs.length();
		int new_length_bits = end - start;
		int new_length_bytes = new_length_bits / 8;
		if (new_length_bits % 8 != 0) {
			new_length_bytes += 1;
		}
		BitSet n = this.bs.get(start, end);
		return new BitArray(n, new_length_bytes);
	}

	/**
	 * Get the bits that match a given mask.
	 *
	 * @param mask the mask that should be matched to
	 * @return a long containing the masked bits
	 */
	public Long trimToMaskLong(BitArray mask) {
		int start = mask.bs.nextSetBit(0);
		if (start < 0) {
			return (long) 0;
		}
		int end = mask.bs.length();

		BitSet n = this.bs.get(start, end);
		long out = 0L;

		if (this.bs.get(end - 1)) {
			// Do two's complement
			for (int i = 0; i < n.length(); ++i) {
				out += n.get(i) ? 0L : (1L << i);
			}
			out += 1;
			out *= -1;
		} else {
			for (int i = 0; i < n.length(); ++i) {
				out += n.get(i) ? (1L << i) : 0L;
			}
		}
		return out;
	}

	@Override
	public String toString() {
		return bs.toString();
	}

	@Override
	public int hashCode() {
		return Objects.hash(bs, numBytes);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		BitArray other = (BitArray) obj;
		return Objects.equals(bs, other.bs) && numBytes == other.numBytes;
	}

	/**
	 * Convert bytes to binary string.
	 *
	 * @return the bits represented as 1s and 0s in a string
	 */
	public String getBinary() {
		StringBuilder out = new StringBuilder();
		for (byte b : toByteArray()) {
			out.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
		}
		return out.toString();
	}

	/**
	 * Convert to a long.
	 *
	 * @return long
	 */
	public long toLong() {
		// TODO: Handle the fact that java uses signed longs...

		byte[] binRep = toByteArray();
		if (binRep.length > 8) {
			throw new RuntimeException("Cannot convert a number this size to a long");
		}
		long out = 0;
		for (byte b : binRep) {
			out = (out << 8) + b;
		}
		return out;
	}

	/**
	 * Convert to a byte array.
	 *
	 * @return byte array
	 */
	public byte[] toByteArray() {
		byte[] arr = Utils.reverse(bs.toByteArray());
		byte[] leadingZeros = new byte[numBytes - arr.length];
		byte[] out = new byte[leadingZeros.length + arr.length];
		// need to add leading zeros since BitSet removes leading zeros
		System.arraycopy(leadingZeros, 0, out, 0, leadingZeros.length);
		System.arraycopy(arr, 0, out, leadingZeros.length, arr.length);
		return out;
	}

	/**
	 * Convert to a list of integers.
	 *
	 * @return list of integers
	 */
	public List<Integer> toIntList() {
		List<Integer> out = new ArrayList<>();
		byte[] bsAsArray = toByteArray();
		int numLeadingZeroInts = toByteArray().length - bsAsArray.length;
		for (int i = 0; i < numLeadingZeroInts; i++) {
			out.add(0);
		}

		for (byte v : bsAsArray) {
			out.add(v & 0xFF);
		}
		// todo: add 0 if empty after ret
		return out;
	}
}
