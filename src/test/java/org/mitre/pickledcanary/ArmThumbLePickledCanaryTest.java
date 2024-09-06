
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.mitre.pickledcanary.search.SavedDataAddresses;

import ghidra.program.database.ProgramBuilder;
import org.junit.Assert;

public class ArmThumbLePickledCanaryTest extends PickledCanaryTest {

	@Override
	protected String getCompileInfoRaw() {
		return ",\"compile_info\":[{\"compiled_using_binary\":[{\"path\":[\"unknown\"],\"compiled_at_address\":[\"01006420\"],\"md5\":[\"unknown\"]}],\"language_id\":[\"ARM:LE:32:v8T\"]}],\"pattern_metadata\":{}}";
	}

	private static final String bnewInstruction = "bne.w `:foo`\n";
	private static final String tablesForbnewInstruction = "";
	// The "expression" portion(s) of these steps have not been verified
	private static final String stepsForbnewInstruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":2,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":3,\"signbit\":false,\"bitstart\":11,\"byteend\":1,\"bigendian\":false,\"bytestart\":1}}},\"right\":{\"op\":\"ConstantValue\",\"value\":19}}},\"right\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":2,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":13,\"shift\":5,\"signbit\":false,\"bitstart\":13,\"byteend\":1,\"bigendian\":false,\"bytestart\":1}}},\"right\":{\"op\":\"ConstantValue\",\"value\":18}}}}},\"right\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":5,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":12}}}}},\"right\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":2,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":10,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":1}}}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[63,0,255,47]}],\"value\":[64,240,0,128]},{\"operands\":[{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Minus\",\"child\":{\"op\":\"ConstantValue\",\"value\":1}},\"right\":{\"op\":\"ConstantValue\",\"value\":20}}},\"right\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":2,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":3,\"signbit\":false,\"bitstart\":11,\"byteend\":1,\"bigendian\":false,\"bytestart\":1}}},\"right\":{\"op\":\"ConstantValue\",\"value\":19}}}}},\"right\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":2,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":13,\"shift\":5,\"signbit\":false,\"bitstart\":13,\"byteend\":1,\"bigendian\":false,\"bytestart\":1}}},\"right\":{\"op\":\"ConstantValue\",\"value\":18}}}}},\"right\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":5,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":12}}}}},\"right\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":2,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":10,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":1}}}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[63,0,255,47]}],\"value\":[64,244,0,128]}],\"mask\":[192,255,0,208]}],\"type\":\"LOOKUP\"}";

	private static final String bnewPatternLabel =
			"bne.w `:foo`\n" +
			"`ANY_BYTES{8,8}`\n" +
			"`foo:`\n" +
			"`ANY_BYTES{1,1}`";

	// Notice this is shorter... will cause the load to be not
	// aligned with our label
	private static final String bnewPatternMisallignedLabel =
			"bne.w `:foo`\n" +
			"`ANY_BYTES{4,4}`\n" +
			"`foo:`\n" +
			"`ANY_BYTES{1,1}`";

	private static final String ldrPattern =
			";`=0x04`\r\n" +
			";`=0x60`\r\n" +
			"`=0x01`\r\n" +
			"`=0x91`\r\n" +
			"ldr r1,[`:Q1`]";

	private static final String ldrPatternMoreSpecific =
			"`=0x04`\r\n" +
			"`=0x60`\r\n" +
			"`=0x01`\r\n" +
			"`=0x91`\r\n" +
			"ldr r1,[`:Q1`]";

	static final int dataBase = 0x0000000;
//	static int bnewOffset = 0x2000000;
	static final int bnewOffset = 0x207e0;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("arm_thumb_le_test", "ARM:LE:32:v8T");

		// This is a bne.w to 0x153c after the start of this instruction
		builder.setBytes(String.format("0x%08X", dataBase), "41 f0 9c 82");

		// the following is:
		// bnew `:foo`
		// mov r8,r8
		// mov r8,r8
		// mov r8,r8
		// mov r8,r8
		// mov r8,r8 // <--- bnew points here
		// mov r8,r8
		builder.setBytes(String.format("0x%08X", dataBase + bnewOffset),
				"40 f0 04 80 c0 46 c0 46 c0 46 c0 46 c0 46 c0 46 ");

		// The following is:
//        0001f0b0 be 88           ldrh       r6,[r7,#0x4]
//        0001f0b2 01 91           str        r1,[sp,#local_16c]
//        0001f0b4 28 49           ldr        r1,[DAT_0001f158]                                = 0001666Ah
//        0001f0b6 00 96           str        r6,[sp,#0x0]=>local_170
//        0001f0b8 02 94           str        r4,[sp,#local_168]
//        0001f0ba 79 44           add        r1=>s_Telling_server_to_connect_to_%d._0003572   = "Telling server to connect to 
//        0001f0bc f7 f7 28 ed     blx        Curl_infof                                       undefined Curl_infof()
//        0001f0c0 dd f8 1c e0     ldr.w      lr,[sp,#local_154]
//        0001f0c4 28 46           mov        r0,r5
//        0001f0c6 3a 88           ldrh       r2,[r7,#0x0]
//        0001f0c8 27 0a           lsrs       r7,r4,#0x8
//        0001f0ca e4 b2           uxtb       r4,r4
//        0001f0cc be f8 06 10     ldrh.w     r1,[lr,#0x6]
//        0001f0d0 be f8 02 30     ldrh.w     r3,[lr,#0x2]
//        0001f0d4 be f8 04 60     ldrh.w     r6,[lr,#0x4]
//        0001f0d8 01 91           str        r1,[sp,#local_16c]
//        0001f0da 20 49           ldr        r1,[DAT_0001f15c]                                = 00016672h
//        0001f0dc 02 97           str        r7,[sp,#local_168]
//        0001f0de 03 94           str        r4,[sp,#local_164]

		builder.setBytes("0x0001f0b0",
				"be 88 01 91 28 49 00 96 02 94 79 44 f7 f7 28 ed dd f8 1c e0 28 46 3a 88 27 0a e4 b2 be f8 06 10 be f8 02 30 be f8 04 60 01 91 20 49 02 97 03 94 ");

		builder.createLabel("0x1008420", "TEST_LABEL");
		builder.createLabel("0x1008424", "TEST_LABEL2");
		builder.createLabel("0x1000424", "TEST_LABEL3");
		setup(builder);
	}

	@Test
	public void testbnewInstruction() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForbnewInstruction + "],\"steps\":["
				+ stepsForbnewInstruction + "]";
		generatePatternTestHelper(bnewInstruction, testQueryPatternExpected + this.getCompileInfo());
	}

	@Test
	public void testbnewInstructionSearch() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), bnewInstruction);
		Assert.assertEquals(2, results.size());

		SavedDataAddresses result = results.get(0);
		Assert.assertEquals(this.program.getMinAddress(), result.getStart());
		Assert.assertEquals(this.program.getMinAddress().add(0x153c), result.labels().get("foo"));

	}

	@Test
	public void testLabelPatternbnew() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), bnewPatternLabel);

		Assert.assertEquals(1, results.size());
		SavedDataAddresses result = results.get(0);
		Assert.assertEquals(this.program.getMinAddress().add(bnewOffset), result.getStart());
		Assert.assertEquals(this.program.getMinAddress().add(bnewOffset + 0xc), result.labels().get("foo"));
	}

	@Test
	public void testMisalignedLabelPatternbnew() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), bnewPatternMisallignedLabel);

		Assert.assertEquals(0, results.size());
	}

	@Test
	public void testLdrPattern() {

		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), ldrPatternMoreSpecific);

		Assert.assertEquals(1, results.size());
		Assert.assertEquals(this.program.getMinAddress().add(0x0001f15c), results.get(0).labels().get("Q1"));

		results = PickledCanary.parseAndRunAll(monitor, this.program, this.program.getMinAddress(), ldrPattern);

		Assert.assertEquals(2, results.size());

		Assert.assertEquals(this.program.getMinAddress().add(0x0001f158), results.get(0).labels().get("Q1"));
		Assert.assertEquals(this.program.getMinAddress().add(0x0001f15c), results.get(1).labels().get("Q1"));
	}
}
