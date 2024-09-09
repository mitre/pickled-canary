
// Copyright (C) 2024 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary;

import org.junit.Assert;
import org.junit.Test;
import org.mitre.pickledcanary.patterngenerator.output.utils.BitArray;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class BitArrayTest extends AbstractGhidraHeadlessIntegrationTest {

	@Test
	public void testBitArray() {
		byte[] maskBytes = new byte[3];
		maskBytes[0] = 0;
		maskBytes[1] = 0xf;
		maskBytes[2] = 0;
		BitArray mask = new BitArray(maskBytes);
		Assert.assertArrayEquals(maskBytes, mask.toByteArray());
		Assert.assertEquals(0xf00L, mask.toLong());

		byte[] dataBytes = new byte[3];
		dataBytes[0] = 0x8;
		dataBytes[1] = 0x43;
		dataBytes[2] = 0x64;
		BitArray data = new BitArray(dataBytes);
		Assert.assertEquals(0x84364L, data.toLong());

		byte[] dataMaskedBytes = new byte[3];
		dataMaskedBytes[0] = 0x0;
		dataMaskedBytes[1] = 0x3;
		dataMaskedBytes[2] = 0x0;
		BitArray dataMasked = new BitArray(dataMaskedBytes);

		Assert.assertArrayEquals(dataMaskedBytes, dataMasked.toByteArray());
		Assert.assertArrayEquals(dataMaskedBytes, data.and(mask).toByteArray());
		Assert.assertEquals(0x300L, dataMasked.toLong());

		byte[] dataMaskedTrimmedBytes = new byte[1];
		dataMaskedTrimmedBytes[0] = 0x3;
		Assert.assertArrayEquals(dataMaskedTrimmedBytes, data.trimToMask(mask).toByteArray());

		byte before = -3;
		int myint = before;
		byte after = (byte) myint;
		Assert.assertEquals(before, after);
	}

	@Test
	public void testBitArrayLong() {

		byte[] valueBytes = new byte[3];
		valueBytes[0] = 0;
		valueBytes[1] = 0x7;
		valueBytes[2] = 0;
		BitArray value = new BitArray(valueBytes);

		byte[] maskBytes = new byte[3];
		maskBytes[0] = 0;
		maskBytes[1] = 0xf;
		maskBytes[2] = 0;
		BitArray mask = new BitArray(maskBytes);

		Assert.assertEquals((Long) 0x7L, value.trimToMaskLong(mask));

		maskBytes = new byte[3];
		maskBytes[0] = 0;
		maskBytes[1] = 0x7;
		maskBytes[2] = 0;
		mask = new BitArray(maskBytes);

		Assert.assertEquals((Long) (-1L), value.trimToMaskLong(mask));

		valueBytes = new byte[3];
		valueBytes[0] = 0;
		valueBytes[1] = 0x45;
		valueBytes[2] = 0;
		value = new BitArray(valueBytes);

		maskBytes = new byte[3];
		maskBytes[0] = 0;
		maskBytes[1] = -1;
		maskBytes[2] = 0;
		mask = new BitArray(maskBytes);

		Assert.assertEquals((Long) (0x45L), value.trimToMaskLong(mask));

	}
}
