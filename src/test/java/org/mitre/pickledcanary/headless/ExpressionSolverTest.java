
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.headless;

import static ghidra.pcode.utils.SlaFormat.ATTRIB_BIGENDIAN;
import static ghidra.pcode.utils.SlaFormat.ATTRIB_ENDBIT;
import static ghidra.pcode.utils.SlaFormat.ATTRIB_ENDBYTE;
import static ghidra.pcode.utils.SlaFormat.ATTRIB_SHIFT;
import static ghidra.pcode.utils.SlaFormat.ATTRIB_SIGNBIT;
import static ghidra.pcode.utils.SlaFormat.ATTRIB_STARTBIT;
import static ghidra.pcode.utils.SlaFormat.ATTRIB_STARTBYTE;
import static ghidra.pcode.utils.SlaFormat.ATTRIB_VAL;
import static ghidra.pcode.utils.SlaFormat.ELEM_CONTEXTFIELD;
import static ghidra.pcode.utils.SlaFormat.ELEM_DIV_EXP;
import static ghidra.pcode.utils.SlaFormat.ELEM_INTB;
import static ghidra.pcode.utils.SlaFormat.ELEM_LSHIFT_EXP;
import static ghidra.pcode.utils.SlaFormat.ELEM_MINUS_EXP;
import static ghidra.pcode.utils.SlaFormat.ELEM_NOT_EXP;
import static ghidra.pcode.utils.SlaFormat.ELEM_PLUS_EXP;
import static ghidra.pcode.utils.SlaFormat.ELEM_RSHIFT_EXP;
import static ghidra.pcode.utils.SlaFormat.ELEM_SUB_EXP;
import static ghidra.pcode.utils.SlaFormat.ELEM_TOKENFIELD;
import static ghidra.pcode.utils.SlaFormat.ELEM_XOR_EXP;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.Assert;
import org.junit.Test;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupDataExpressionSolver;

import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.DecoderException;
import ghidra.program.model.pcode.PackedDecode;
import ghidra.program.model.pcode.PatchPackedEncode;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

/**
 * Tests solving expressions using the expression solver.
 *
 * The general idea of this is lifted from SolverTest.java
 */
public class ExpressionSolverTest extends AbstractGhidraHeadlessIntegrationTest {

	private PatternExpression getExpressionInstance(PatchPackedEncode encode)
			throws DecoderException, IOException {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		// Write encoded expression to output stream
		encode.writeTo(outputStream);
		// Get the data written to output stream as byte[]
		byte[] bytes = outputStream.toByteArray();

		PackedDecode decode = new PackedDecode();
		// Set the maximum bytes to 1024.
		decode.open(1024, "test");

		// Ingest the bytes at offset 0
		decode.ingestBytes(bytes, 0, bytes.length);
		decode.endIngest();

		// Decode the expression into the object
		return PatternExpression.decodeExpression(decode, null);
	}

	@Test
	public void testPlusExp() throws DecoderException, IOException {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_PLUS_EXP);
		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 4);
		encode.closeElement(ELEM_INTB);

		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 4);
		encode.closeElement(ELEM_INTB);
		encode.closeElement(ELEM_PLUS_EXP);

		// 4 + 4

		// Solve the expression
		PatternExpression expression = getExpressionInstance(encode);
		long result = LookupDataExpressionSolver.computeExpression(expression, null, null, 0, 0);
		Assert.assertEquals(8, result);
	}

	@Test
	public void testRShiftExp() throws DecoderException, IOException {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_RSHIFT_EXP);
		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 44);
		encode.closeElement(ELEM_INTB);

		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 2);
		encode.closeElement(ELEM_INTB);
		encode.closeElement(ELEM_RSHIFT_EXP);

		// 44 >> 2

		// Solve the expression
		PatternExpression expression = getExpressionInstance(encode);
		long result = LookupDataExpressionSolver.computeExpression(expression, null, null, 0, 0);
		Assert.assertEquals(11, result);
	}

	@Test
	public void testLShiftExp() throws DecoderException, IOException {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_LSHIFT_EXP);
		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 43);
		encode.closeElement(ELEM_INTB);

		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 4);
		encode.closeElement(ELEM_INTB);
		encode.closeElement(ELEM_LSHIFT_EXP);

		// 43 << 4

		// Solve the expression
		PatternExpression expression = getExpressionInstance(encode);
		long result = LookupDataExpressionSolver.computeExpression(expression, null, null, 0, 0);
		Assert.assertEquals(688, result);
	}

	@Test
	public void testSubExp() throws DecoderException, IOException {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_SUB_EXP);
		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 43);
		encode.closeElement(ELEM_INTB);

		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 4);
		encode.closeElement(ELEM_INTB);
		encode.closeElement(ELEM_SUB_EXP);

		// 43 - 4

		// Solve the expression
		PatternExpression expression = getExpressionInstance(encode);
		long result = LookupDataExpressionSolver.computeExpression(expression, null, null, 0, 0);
		Assert.assertEquals(39, result);
	}

	@Test
	public void testDivExp() throws DecoderException, IOException {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_DIV_EXP);
		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 80);
		encode.closeElement(ELEM_INTB);

		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 4);
		encode.closeElement(ELEM_INTB);
		encode.closeElement(ELEM_DIV_EXP);

		// 80/4

		// Solve the expression
		PatternExpression expression = getExpressionInstance(encode);
		long result = LookupDataExpressionSolver.computeExpression(expression, null, null, 0, 0);
		Assert.assertEquals(20, result);
	}

	@Test
	public void testXORExp() throws DecoderException, IOException {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_XOR_EXP);
		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 123);
		encode.closeElement(ELEM_INTB);

		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 33);
		encode.closeElement(ELEM_INTB);
		encode.closeElement(ELEM_XOR_EXP);

		// 123 ^ 33

		// Solve the expression
		PatternExpression expression = getExpressionInstance(encode);
		long result = LookupDataExpressionSolver.computeExpression(expression, null, null, 0, 0);
		Assert.assertEquals(90, result);
	}

	@Test
	public void testNotExp() throws DecoderException, IOException {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_NOT_EXP);
		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 1);
		encode.closeElement(ELEM_INTB);

		encode.closeElement(ELEM_NOT_EXP);

		// ~1

		// Solve the expression
		PatternExpression expression = getExpressionInstance(encode);
		long result = LookupDataExpressionSolver.computeExpression(expression, null, null, 0, 0);
		Assert.assertEquals(0xFFFFFFFE, result);
	}

	@Test
	public void testMinusExpression() throws DecoderException, IOException {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_MINUS_EXP);
		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 10);
		encode.closeElement(ELEM_INTB);
		encode.closeElement(ELEM_MINUS_EXP);
		// -10

		PatternExpression expression = getExpressionInstance(encode);

		long result = LookupDataExpressionSolver.computeExpression(expression, null, null, 0, 0);

		Assert.assertEquals(-10, result);
	}

	@Test
	public void testConstantValueExpression()
			throws DecoderException, IOException {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 42);
		encode.closeElement(ELEM_INTB);
		// 42

		PatternExpression expression = getExpressionInstance(encode);

		long result = LookupDataExpressionSolver.computeExpression(expression, null, null, 0, 0);

		Assert.assertEquals(42, result);
	}

	@Test
	public void testContextFieldExpression()
			throws DecoderException, IOException {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_CONTEXTFIELD);
		encode.writeBool(ATTRIB_SIGNBIT, false);
		encode.writeSignedInteger(ATTRIB_STARTBIT, 28);
		encode.writeSignedInteger(ATTRIB_ENDBIT, 31);
		encode.writeSignedInteger(ATTRIB_STARTBYTE, 3);
		encode.writeSignedInteger(ATTRIB_ENDBYTE, 3);
		encode.writeSignedInteger(ATTRIB_SHIFT, 0);
		encode.closeElement(ELEM_CONTEXTFIELD);

		PatternExpression expression = getExpressionInstance(encode);

		int[] context = { 0x89ABCDEF };
		long result = LookupDataExpressionSolver.computeExpression(expression, null, context, 0, 0);

		Assert.assertEquals(15, result);
	}

	@Test
	public void testTokenFieldExpression()
			throws Exception {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_TOKENFIELD);
		encode.writeBool(ATTRIB_BIGENDIAN, false);
		encode.writeBool(ATTRIB_SIGNBIT, false);
		encode.writeSignedInteger(ATTRIB_STARTBIT, 0);
		encode.writeSignedInteger(ATTRIB_ENDBIT, 5);
		encode.writeSignedInteger(ATTRIB_STARTBYTE, 3);
		encode.writeSignedInteger(ATTRIB_ENDBYTE, 3);
		encode.writeSignedInteger(ATTRIB_SHIFT, 0);
		encode.closeElement(ELEM_TOKENFIELD);

		PatternExpression expression = getExpressionInstance(encode);

		byte[] data = { 0, 0, 0, 0x7a };

		ProgramBuilder builder = new ProgramBuilder("arm_le_test", "ARM:LE:32:v8");
		Program program = builder.getProgram();
		MemBuffer b = new ByteMemBufferImpl(program.getMinAddress(), data, false);

		long result = LookupDataExpressionSolver.computeExpression(expression, b, null, 0, 0);

		Assert.assertEquals(58, result);
	}

	@Test
	public void testComplexExpression()
			throws Exception {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();

		encode.openElement(ELEM_XOR_EXP);

		encode.openElement(ELEM_LSHIFT_EXP);

		encode.openElement(ELEM_PLUS_EXP);
		encode.openElement(ELEM_TOKENFIELD);
		encode.writeBool(ATTRIB_BIGENDIAN, false);
		encode.writeBool(ATTRIB_SIGNBIT, false);
		encode.writeSignedInteger(ATTRIB_STARTBIT, 0);
		encode.writeSignedInteger(ATTRIB_ENDBIT, 5);
		encode.writeSignedInteger(ATTRIB_STARTBYTE, 3);
		encode.writeSignedInteger(ATTRIB_ENDBYTE, 3);
		encode.writeSignedInteger(ATTRIB_SHIFT, 0);
		encode.closeElement(ELEM_TOKENFIELD);

		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 4);
		encode.closeElement(ELEM_INTB);
		encode.closeElement(ELEM_PLUS_EXP);

		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 2);
		encode.closeElement(ELEM_INTB);
		encode.closeElement(ELEM_LSHIFT_EXP);

		encode.openElement(ELEM_CONTEXTFIELD);
		encode.writeBool(ATTRIB_SIGNBIT, false);
		encode.writeSignedInteger(ATTRIB_STARTBIT, 28);
		encode.writeSignedInteger(ATTRIB_ENDBIT, 31);
		encode.writeSignedInteger(ATTRIB_STARTBYTE, 3);
		encode.writeSignedInteger(ATTRIB_ENDBYTE, 3);
		encode.writeSignedInteger(ATTRIB_SHIFT, 0);
		encode.closeElement(ELEM_CONTEXTFIELD);

		encode.closeElement(ELEM_XOR_EXP);

		// ((((bits 0-5 of 0x7a [aka: 58]) + 4) << 2) ^ (bits 28-31 of 0x89abcdef [aka: 15]) == 247

		PatternExpression expression = getExpressionInstance(encode);

		byte[] data = { 0, 0, 0, 0x7a };

		ProgramBuilder builder = new ProgramBuilder("arm_le_test", "ARM:LE:32:v8");
		Program program = builder.getProgram();
		MemBuffer b = new ByteMemBufferImpl(program.getMinAddress(), data, false);

		int[] context = { 0x89ABCDEF };
		long result = LookupDataExpressionSolver.computeExpression(expression, b, context, 0, 0);

		Assert.assertEquals(247, result);
	}

	@Test
	public void testLongContextFieldExpression()
			throws DecoderException, IOException {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_CONTEXTFIELD);
		encode.writeBool(ATTRIB_SIGNBIT, false);
		encode.writeSignedInteger(ATTRIB_STARTBIT, 16);
		encode.writeSignedInteger(ATTRIB_ENDBIT, 24);
		encode.writeSignedInteger(ATTRIB_STARTBYTE, 0);
		encode.writeSignedInteger(ATTRIB_ENDBYTE, 9);
		encode.writeSignedInteger(ATTRIB_SHIFT, 0);
		encode.closeElement(ELEM_CONTEXTFIELD);

		PatternExpression expression = getExpressionInstance(encode);

		int[] context = { 0x89ABCDEF, 0x01020304, 0x05060708 };
		long result = LookupDataExpressionSolver.computeExpression(expression, null, context, 0, 0);

		Assert.assertEquals(262, result);
	}

	@Test
	public void testLongTokenFieldExpression()
			throws Exception {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_TOKENFIELD);
		encode.writeBool(ATTRIB_BIGENDIAN, false);
		encode.writeBool(ATTRIB_SIGNBIT, false);
		encode.writeSignedInteger(ATTRIB_STARTBIT, 0);
		encode.writeSignedInteger(ATTRIB_ENDBIT, 5);
		encode.writeSignedInteger(ATTRIB_STARTBYTE, 3);
		encode.writeSignedInteger(ATTRIB_ENDBYTE, 9);
		encode.writeSignedInteger(ATTRIB_SHIFT, 0);
		encode.closeElement(ELEM_TOKENFIELD);

		PatternExpression expression = getExpressionInstance(encode);

		byte[] data = { 0, 0, 0, 0x7a, 1, 2, 3, 4, 5, 6 };

		ProgramBuilder builder = new ProgramBuilder("arm_le_test", "ARM:LE:32:v8");
		Program program = builder.getProgram();
		MemBuffer b = new ByteMemBufferImpl(program.getMinAddress(), data, false);

		long result = LookupDataExpressionSolver.computeExpression(expression, b, null, 0, 0);

		Assert.assertEquals(3, result);
	}
}
