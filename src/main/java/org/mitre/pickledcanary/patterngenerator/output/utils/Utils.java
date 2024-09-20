
// Copyright (C) 2024 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.utils;

public class Utils {
	private Utils() {
	}

	/**
	 * Reverse order of byte array. Used to convert from big to little endian and vice versa.
	 * 
	 * @param arr
	 *            the byte array to reverse
	 * @return a new reversed byte array
	 */
	public static byte[] reverse(byte[] arr) {
		byte[] reversed = new byte[arr.length];
		for (int i = 0; i < arr.length; i++) {
			reversed[i] = arr[arr.length - i - 1];
		}
		return reversed;
	}
}
