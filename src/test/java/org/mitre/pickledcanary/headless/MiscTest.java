
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.headless;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;
import org.mitre.pickledcanary.patterngenerator.output.steps.AnyByteSequence;
import org.mitre.pickledcanary.patterngenerator.output.steps.FieldOperandMeta;
import org.mitre.pickledcanary.patterngenerator.output.steps.InstructionEncoding;
import org.mitre.pickledcanary.patterngenerator.output.steps.OperandMeta;
import org.mitre.pickledcanary.patterngenerator.output.steps.ScalarOperandMeta;
import org.mitre.pickledcanary.patterngenerator.output.utils.BitArray;
import org.mitre.pickledcanary.patterngenerator.output.utils.OperandRepresentation;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class MiscTest extends AbstractGhidraHeadlessIntegrationTest {

	@Test
	public void testInstructionEncodingCompare() {
		byte[] value = new byte[4];
		InstructionEncoding a = new InstructionEncoding(value);
		InstructionEncoding b = new InstructionEncoding(value);

		OperandMeta op1a = new FieldOperandMeta(Arrays.asList(1, 2, 3, 4), "tablekey", "Op1");
		OperandMeta op2a = new FieldOperandMeta(Arrays.asList(1, 2, 3, 4), "tablekey", "Op2");
		OperandMeta op2b = new FieldOperandMeta(Arrays.asList(1, 2, 3, 5), "tablekey", "Op2");

		a.addOperand(op1a);
		b.addOperand(op1a);

		Assert.assertEquals(0, a.compareTo(b));

		a.addOperand(op2a);

		Assert.assertEquals(1, a.compareTo(b));

		b.addOperand(op2b);

		Assert.assertEquals(-1, a.compareTo(b));

		// Make sure if they have different values they're different
		b = new InstructionEncoding(new byte[5]);
		Assert.assertEquals(-1, a.compareTo(b));

		// Scalar vs Field operand
		b = new InstructionEncoding(value);
		b.addOperand(new ScalarOperandMeta(Arrays.asList(1, 2), "q2", null));
		b.addOperand(op1a);
		Assert.assertEquals(-1, a.compareTo(b));
		Assert.assertEquals(1, b.compareTo(a));

		// Different Operand varId
		b = new InstructionEncoding(value);
		b.addOperand(op1a);
		b.addOperand(new FieldOperandMeta(Arrays.asList(1, 2, 3, 4), "tablekey", "oops"));
		Assert.assertEquals(-32, a.compareTo(b));

		// Different operand mask size
		b = new InstructionEncoding(value);
		b.addOperand(op1a);
		b.addOperand(new FieldOperandMeta(Arrays.asList(1, 2, 3, 4, 5), "tablekey", "Op2"));
		Assert.assertEquals(-1, a.compareTo(b));
	}

	@Test
	public void testAnyByteSequence() {
		AnyByteSequence a = new AnyByteSequence(0, 10, 2);

		Assert.assertEquals("ANY_BYTES{0,10,2}", a.toString());

		a.setMin(5);
		a.setMax(15);
		a.setInterval(5);
		Assert.assertEquals("ANY_BYTES{5,15,5}", a.toString());

		a.setInterval(null);
		Assert.assertEquals("ANY_BYTES{5,15}", a.toString());

		IllegalArgumentException e = Assert.assertThrows(IllegalArgumentException.class, () -> {
			a.setMax(0);
		});

		Assert.assertEquals(
			"ANY_BYTES min and max must be nonnegative, min must be smaller than or equal to max, and interval must be positive: `ANY_BYTES{5,0}`",
			e.getMessage());

		Assert.assertEquals(5, a.getMin());
		Assert.assertEquals(15, a.getMax());
		Assert.assertEquals(null, a.getInterval());
		Assert.assertEquals("{\"min\":5,\"max\":15,\"type\":\"ANYBYTESEQUENCE\"}",
			a.getJson().toString());

		a.setInterval(2);
		Assert.assertEquals("{\"min\":5,\"max\":15,\"interval\":2,\"type\":\"ANYBYTESEQUENCE\"}",
			a.getJson().toString());

		a.setMinMaxInterval(1, 2, null);
		Assert.assertEquals("ANY_BYTES{1,2,1}", a.toString());

		e = Assert.assertThrows(IllegalArgumentException.class, () -> {
			a.setMin(-1);
		});
		Assert.assertEquals(
			"ANY_BYTES min and max must be nonnegative, min must be smaller than or equal to max, and interval must be positive: `ANY_BYTES{-1,2,1}`",
			e.getMessage());

		e = Assert.assertThrows(IllegalArgumentException.class, () -> {
			a.setInterval(-1);
		});
		Assert.assertEquals(
			"ANY_BYTES min and max must be nonnegative, min must be smaller than or equal to max, and interval must be positive: `ANY_BYTES{1,2,-1}`",
			e.getMessage());

		e = Assert.assertThrows(IllegalArgumentException.class, () -> {
			a.setInterval(0);
		});
		Assert.assertEquals(
			"ANY_BYTES min and max must be nonnegative, min must be smaller than or equal to max, and interval must be positive: `ANY_BYTES{1,2,0}`",
			e.getMessage());

		e = Assert.assertThrows(IllegalArgumentException.class, () -> {
			a.setMax(-1);
		});
		Assert.assertEquals(
			"ANY_BYTES min and max must be nonnegative, min must be smaller than or equal to max, and interval must be positive: `ANY_BYTES{1,-1,1}`",
			e.getMessage());

		e = Assert.assertThrows(IllegalArgumentException.class, () -> {
			a.setInterval(10);
		});
		Assert.assertEquals("ANY_BYTES interval must be less than (max-min): `ANY_BYTES{1,2,10}`",
			e.getMessage());

		a.setMinMaxInterval(4, 4, 4);
		Assert.assertEquals("ANY_BYTES{4,4,4}", a.toString());

		AnyByteSequence b = new AnyByteSequence(4,4,4, "test");
		Assert.assertEquals("ANY_BYTES{4,4,4}", b.toString());
	}

	@Test
	public void testBitArray() {
		BitArray a = new BitArray(4);
		BitArray b = new BitArray(2);

		b = b.not();

		BitArray c = new BitArray(new byte[] {-128,0,0,0});

		BitArray d = a.or(c);
		BitArray e = d.or(b);

		Assert.assertEquals("{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 31}", e.toString());

		Assert.assertEquals("10000000000000001111111111111111", e.getBinary());
	}

	@Test
	public void testOperandRepresentation() {

		OperandRepresentation a = new OperandRepresentation(Arrays.asList(1,2,3), Arrays.asList(1,2,3) );
		OperandRepresentation b = new OperandRepresentation(Arrays.asList(1,2,5), Arrays.asList(1,2,3) );

		Assert.assertTrue(a.equals(a));
		Assert.assertFalse(a.equals(null));
		Assert.assertFalse(a.equals(1));
		Assert.assertFalse(a.equals(b));

		IllegalArgumentException error = Assert.assertThrows(IllegalArgumentException.class, () -> {
			new OperandRepresentation(null, Arrays.asList(1,2));
		});
		Assert.assertEquals("Mask must not be null", error.getMessage());

		error = Assert.assertThrows(IllegalArgumentException.class, () -> {
			new OperandRepresentation(Arrays.asList(1,2), null);
		});
		Assert.assertEquals("Value must not be null", error.getMessage());

		error = Assert.assertThrows(IllegalArgumentException.class, () -> {
			new OperandRepresentation(Arrays.asList(1), Arrays.asList(1,2));
		});
		Assert.assertEquals("Mask and Value must be the same length", error.getMessage());

		Assert.assertEquals(0, a.compareTo(a));
		Assert.assertEquals(-1, a.compareTo(b));

		b = new OperandRepresentation(Arrays.asList(1,2,3), Arrays.asList(1,2,4));
		Assert.assertEquals(-1, a.compareTo(b));
		Assert.assertFalse(a.equals(b));

		b = new OperandRepresentation(Arrays.asList(1,2), Arrays.asList(1,2));
		Assert.assertEquals(1, a.compareTo(b));

		Assert.assertEquals("{M:[1, 2], V:[1, 2]}", b.toString());
	}
}
