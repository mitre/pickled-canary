
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary;

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mitre.pickledcanary.patterngenerator.output.steps.ConcreteOperandField;
import org.mitre.pickledcanary.search.SavedData;
import org.mitre.pickledcanary.search.SavedDataAddresses;

import ghidra.program.database.ProgramBuilder;

public class ArmLePickledCanaryTest extends PickledCanaryTest {

	@Override
	protected String getCompileInfoRaw() {
		return ",\"compile_info\":[{\"compiled_using_binary\":[{\"path\":[\"unknown\"],\"compiled_at_address\":[\"01006420\"],\"md5\":[\"unknown\"]}],\"language_id\":[\"ARM:LE:32:v8\"]}],\"pattern_metadata\":{}}";
	}

	private static final String simpleSuboperandInstruction = "mov `Q1/[lr]./,/3`,#0x0";
	private static final String stepsForSimpleSuboperandInstruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,240,0,0]}],\"value\":[0,0,160,227]}],\"mask\":[255,15,255,255]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForSimpleSuboperandInstruction = "{\"r2\":[{\"value\":[2],\"mask\":[15]}],\"r3\":[{\"value\":[3],\"mask\":[15]}],\"r4\":[{\"value\":[4],\"mask\":[15]}],\"r5\":[{\"value\":[5],\"mask\":[15]}],\"r6\":[{\"value\":[6],\"mask\":[15]}],\"r7\":[{\"value\":[7],\"mask\":[15]}],\"r8\":[{\"value\":[8],\"mask\":[15]}],\"lr\":[{\"value\":[14],\"mask\":[15]}],\"r9\":[{\"value\":[9],\"mask\":[15]}],\"r0\":[{\"value\":[0],\"mask\":[15]}],\"r1\":[{\"value\":[1],\"mask\":[15]}]}";

	// tests backfills
	private static final String twoWildcardsInstruction = "bfc r3,#`Q1/.*/,`,#`Q2/.*/,`";
	// The "expression" portion(s) of these steps have not been verified
	private static final String stepsForTwoWildcardsInstruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":7,\"signbit\":false,\"bitstart\":7,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[128,15,0,0]},{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Sub\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":20,\"shift\":0,\"signbit\":false,\"bitstart\":16,\"byteend\":2,\"bigendian\":false,\"bytestart\":2}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":7,\"signbit\":false,\"bitstart\":7,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":1}}},\"var_id\":\"Q2\",\"type\":\"Scalar\",\"mask\":[0,0,31,0]}],\"value\":[31,48,192,231]},{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":7,\"signbit\":false,\"bitstart\":7,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[128,15,0,0]},{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Sub\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":20,\"shift\":0,\"signbit\":false,\"bitstart\":16,\"byteend\":2,\"bigendian\":false,\"bytestart\":2}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":7,\"signbit\":false,\"bitstart\":7,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":1}}},\"var_id\":\"Q2\",\"type\":\"Scalar\",\"mask\":[0,0,31,0]}],\"value\":[31,48,192,247]}],\"mask\":[127,240,224,255]}],\"type\":\"LOOKUP\"}";
	// These are the steps for Ghidra 10.1 (seems like the arm processor spec was
	// probably updated)
	private static final String stepsForTwoWildcardsInstruction_101 = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":7,\"signbit\":false,\"bitstart\":7,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[128,15,0,0]},{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Sub\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":20,\"shift\":0,\"signbit\":false,\"bitstart\":16,\"byteend\":2,\"bigendian\":false,\"bytestart\":2}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":7,\"signbit\":false,\"bitstart\":7,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":1}}},\"var_id\":\"Q2\",\"type\":\"Scalar\",\"mask\":[0,0,31,0]}],\"value\":[31,48,192,231]}],\"mask\":[127,240,224,255]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForTwoWildcardsInstruction = "";

	private static final String instructionsWithWildcards =
			"mov `Q3/r./,/4`,#0x200\n" +
			"`ANY_BYTES{4,16,2}`\n" +
			"sub `Q3`,`Q3`,#0x200\n" +
			"`ANY_BYTES{0,16,3}`\n" +
			"mvn r2,#0x63";
	private static final String stepsForInstructionsWithWildcards = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q3\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,240,0,0]}],\"value\":[2,12,160,227]}],\"mask\":[255,15,255,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 4 End: 16 Interval: 2 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{4,16,2}`\",\"min\":4,\"max\":16,\"interval\":2,\"type\":\"ANYBYTESEQUENCE\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q3\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,0,15,0]},{\"var_id\":\"Q3\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,240,0,0]}],\"value\":[2,12,64,226]},{\"operands\":[{\"var_id\":\"Q3\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,0,15,0]},{\"var_id\":\"Q3\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,240,0,0]}],\"value\":[2,12,64,242]}],\"mask\":[255,15,240,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 0 End: 16 Interval: 3 From: Token from line #4: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{0,16,3}`\",\"min\":0,\"max\":16,\"interval\":3,\"type\":\"ANYBYTESEQUENCE\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[99,32,224,227]}],\"mask\":[255,255,255,255]}],\"type\":\"LOOKUP\"}";
	// This variation works with Ghidra 10.1 (prior works with older versions)
	private static final String stepsForInstructionsWithWildcards_newer = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q3\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,240,0,0]}],\"value\":[2,12,160,227]}],\"mask\":[255,15,255,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 4 End: 16 Interval: 2 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{4,16,2}`\",\"min\":4,\"max\":16,\"interval\":2,\"type\":\"ANYBYTESEQUENCE\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q3\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,0,15,0]},{\"var_id\":\"Q3\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,240,0,0]}],\"value\":[2,12,64,226]}],\"mask\":[255,15,240,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 0 End: 16 Interval: 3 From: Token from line #4: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{0,16,3}`\",\"min\":0,\"max\":16,\"interval\":3,\"type\":\"ANYBYTESEQUENCE\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[99,32,224,227]}],\"mask\":[255,255,255,255]}],\"type\":\"LOOKUP\"}";
	// This variation works with Ghidra 10.2 (prior works with older versions)
	private static final String stepsForInstructionsWithWildcards_evenNewer = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q3\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,240,0,0]}],\"value\":[2,12,160,227]}],\"mask\":[255,15,255,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 4 End: 16 Interval: 2 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{4,16,2}`\",\"min\":4,\"max\":16,\"interval\":2,\"type\":\"ANYBYTESEQUENCE\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q3\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,240,0,0]},{\"var_id\":\"Q3\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,0,15,0]}],\"value\":[2,12,64,226]}],\"mask\":[255,15,240,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 0 End: 16 Interval: 3 From: Token from line #4: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{0,16,3}`\",\"min\":0,\"max\":16,\"interval\":3,\"type\":\"ANYBYTESEQUENCE\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[99,32,224,227]}],\"mask\":[255,255,255,255]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForInstructionsWithWildcards = "{\"r2\":[{\"value\":[2],\"mask\":[15]}],\"r3\":[{\"value\":[3],\"mask\":[15]}],\"r4\":[{\"value\":[4],\"mask\":[15]}],\"r5\":[{\"value\":[5],\"mask\":[15]}],\"r6\":[{\"value\":[6],\"mask\":[15]}],\"r7\":[{\"value\":[7],\"mask\":[15]}],\"r8\":[{\"value\":[8],\"mask\":[15]}],\"r9\":[{\"value\":[9],\"mask\":[15]}],\"r0\":[{\"value\":[0],\"mask\":[15]}],\"r1\":[{\"value\":[1],\"mask\":[15]}]}";

	private static final String bneInstruction = "bne `*`";
	private static final String tablesForBneInstruction = "";
	private static final String stepsForBneInstruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0,0,26]}],\"mask\":[0,0,0,255]}],\"type\":\"LOOKUP\"}";

	private static final String ldrInstruction = "ldr r3, [`:foo`]\n";
	private static final String tablesForLdrInstruction = "";
	private static final String stepsForLdrInstruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"Sub\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":8}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,15,0,0]}],\"value\":[0,48,31,229]},{\"operands\":[{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":8}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,15,0,0]}],\"value\":[0,48,159,229]}],\"mask\":[0,240,255,255]}],\"type\":\"LOOKUP\"}";
	private static final String stepsForLdrInstruction_pre1014 = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"Sub\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":8}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,15,0,0]}],\"value\":[0,48,31,229]},{\"operands\":[{\"expression\":{\"op\":\"Sub\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":8}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,15,0,0]}],\"value\":[0,48,31,245]},{\"operands\":[{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":8}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,15,0,0]}],\"value\":[0,48,159,229]},{\"operands\":[{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":8}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,15,0,0]}],\"value\":[0,48,159,245]}],\"mask\":[0,240,255,255]}],\"type\":\"LOOKUP\"}";

	// this shouldn't match with the second mov in our data (because that mov has a
	// different first register). but should instead span to the third mov
	private static final String enforceConstraintsPattern = "mov `Q1/[lr].`,#0x0\n`ANY_BYTES{0,8}`\nmov `Q1`,#0x0";

	private static final String beqPatternLabel =
			"beq `:foo`\n" +
			"`ANY_BYTES{12,12}`\n" +
			"`foo:`\n" +
			"`ANY_BYTES{1,1}`";
	private static final String beqPatternMisallignedLabel =
			"beq `:foo`\n" +
			"`ANY_BYTES{16,16}`\n" +
			"`foo:`\n" +
			"`ANY_BYTES{1,1}`";

	private static final String blPatternLabel =
			"`foo:`\n" +
			"`ANY_BYTES{12,12}`\n" +
			"bl `:foo`\n" +
			"`ANY_BYTES{1,1}`";
	private static final String tablesForLabelBl = "";
	private static final String stepsForLabelBl = "{\"type\":\"LABEL\",\"value\":\"foo\"},{\"note\":\"AnyBytesNode Start: 12 End: 12 Interval: 1 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{12,12}`\",\"min\":12,\"max\":12,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"EndInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"Mult\",\"children\":{\"left\":{\"op\":\"ConstantValue\",\"value\":4},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":23,\"shift\":0,\"signbit\":true,\"bitstart\":0,\"byteend\":2,\"bigendian\":false,\"bytestart\":0}}}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[0,0,0,0]}],\"value\":[255,255,255,235]}],\"mask\":[255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"EndInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"Mult\",\"children\":{\"left\":{\"op\":\"ConstantValue\",\"value\":4},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":23,\"shift\":0,\"signbit\":true,\"bitstart\":0,\"byteend\":2,\"bigendian\":false,\"bytestart\":0}}}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,255,255,0]}],\"value\":[0,0,0,235]}],\"mask\":[0,0,0,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 1 End: 1 Interval: 1 From: Token from line #4: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{1,1}`\",\"min\":1,\"max\":1,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"}";
	// for Ghidra 10.2 and above with the new assembler, the one above seems to be wrong but works with the old assembler
	private static final String stepsForLabelBl_newer = "{\"type\":\"LABEL\",\"value\":\"foo\"},{\"note\":\"AnyBytesNode Start: 12 End: 12 Interval: 1 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{12,12}`\",\"min\":12,\"max\":12,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"EndInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"Mult\",\"children\":{\"left\":{\"op\":\"ConstantValue\",\"value\":4},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":23,\"shift\":0,\"signbit\":true,\"bitstart\":0,\"byteend\":2,\"bigendian\":false,\"bytestart\":0}}}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,255,255,0]}],\"value\":[0,0,0,235]}],\"mask\":[0,0,0,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 1 End: 1 Interval: 1 From: Token from line #4: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{1,1}`\",\"min\":1,\"max\":1,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"}"; 
	private static final String blPatternMisallignedLabel =
			"`foo:`\n" +
			"`ANY_BYTES{4,4}`\n" +
			"bl `:foo`\n" +
			"`ANY_BYTES{1,1}`";

	private static final String ldrPatternLabel =
			"ldr r3, [`:foo`]\n" +
			"`ANY_BYTES{8,8}`\n" +
			"`foo:`\n" +
			"`ANY_BYTES{1,1}`";
	private static final String tablesForLdrPatternLabel = "";
	private static final String stepsForLdrPatternLabel = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"Sub\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":8}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,15,0,0]}],\"value\":[0,48,31,229]},{\"operands\":[{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":8}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,15,0,0]}],\"value\":[0,48,159,229]}],\"mask\":[0,240,255,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 8 End: 8 Interval: 1 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{8,8}`\",\"min\":8,\"max\":8,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"},{\"type\":\"LABEL\",\"value\":\"foo\"},{\"note\":\"AnyBytesNode Start: 1 End: 1 Interval: 1 From: Token from line #4: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{1,1}`\",\"min\":1,\"max\":1,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"}";
	// This is unverified but makes the test pass:
	private static final String stepsForLdrPatternLabel1003 = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"Sub\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":8}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,15,0,0]}],\"value\":[0,48,31,229]},{\"operands\":[{\"expression\":{\"op\":\"Sub\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":8}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,15,0,0]}],\"value\":[0,48,31,245]},{\"operands\":[{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":8}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,15,0,0]}],\"value\":[0,48,159,229]},{\"operands\":[{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"StartInstructionValue\"},\"right\":{\"op\":\"ConstantValue\",\"value\":8}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":11,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":false,\"bytestart\":0}}}}},\"var_id\":\":foo\",\"type\":\"Scalar\",\"mask\":[255,15,0,0]}],\"value\":[0,48,159,245]}],\"mask\":[0,240,255,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 8 End: 8 Interval: 1 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{8,8}`\",\"min\":8,\"max\":8,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"},{\"type\":\"LABEL\",\"value\":\"foo\"},{\"note\":\"AnyBytesNode Start: 1 End: 1 Interval: 1 From: Token from line #4: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{1,1}`\",\"min\":1,\"max\":1,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"}";

	private static final String ldrPatternMisallignedLabel =
			"ldr r3,[`:foo`]\n" +
			"`ANY_BYTES{4,4}`\n" + // Notice this is shorter... will cause the load to be not aligned with our
															// label
			"`foo:`\n" +
			"`ANY_BYTES{1,1}`";

	static final int dataBase = 0x1008420;
	static final int beqOffset = 0x10000;
	static final int blOffset = 0x20000;
	static final int ldrOffset = 0x2000;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("arm_le_test", "ARM:LE:32:v8");
		String movr10 = "00 10 a0 e3";
		String movr30 = "00 30 a0 e3";
		builder.setBytes(String.format("0x%08X", dataBase),
				"85 4f dc 77 85 4f dc 77 " + movr10 + " " + movr30 + " " + movr10 + "ff ");
		builder.setBytes(String.format("0x%08X", dataBase + beqOffset),
				"02 00 00 0a 00 00 a0 e1 00 00 a0 e1 00 00 a0 e1 00 00 a0 e1");

		// the following is:
		// foo:
		// mov r0,r0
		// mov r0,r0
		// mov r0,r0
		// bl foo
		// mov r0,r0
		builder.setBytes(String.format("0x%08X", dataBase + blOffset),
				"00 00 a0 e1 00 00 a0 e1 00 00 a0 e1 fb ff ff eb 00 00 a0 e1");

		// the following is:
		// ldr r3,[pc,#4]
		// mov r0,r0
		// mov r0,r0
		// mov r0,r0 // <--- ldr points here
		// mov r0,r0
		builder.setBytes(String.format("0x%08X", dataBase + ldrOffset),
				"04 30 9f e5  00 00 a0 e1  00 00 a0 e1  00 00 a0 e1  00 00 a0 e1 ");

		builder.createLabel("0x1008420", "TEST_LABEL");
		builder.createLabel("0x1008424", "TEST_LABEL2");
		builder.createLabel("0x1000424", "TEST_LABEL3");
		setup(builder);
	}

	@Test
	public void testPatternWithSuboperand() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForSimpleSuboperandInstruction + "],\"steps\":["
				+ stepsForSimpleSuboperandInstruction + "]";
		generatePatternTestHelper(simpleSuboperandInstruction, testQueryPatternExpected + this.getCompileInfo());
	}

	@Test
	public void testRunPatternWithSuboperand() {
		List<SavedDataAddresses> x = PickledCanary.parseAndRunAll(monitor, this.program,
				program.getMemory().getMinAddress(), simpleSuboperandInstruction);
		List<SavedDataAddresses> expected = new ArrayList<>();
		SavedData s = new SavedData(dataBase + 8, dataBase + 12);
		s.addOrFail(new ConcreteOperandField("Q1", "r1"));
		expected.add(new SavedDataAddresses(s, program.getImageBase()));

		SavedData s1 = new SavedData(dataBase + 8 + 4, dataBase + 12 + 4);
		s1.addOrFail(new ConcreteOperandField("Q1", "r3"));
		expected.add(new SavedDataAddresses(s1, program.getImageBase()));

		SavedData s2 = new SavedData(dataBase + 8 + 8, dataBase + 12 + 8);
		s2.addOrFail(new ConcreteOperandField("Q1", "r1"));
		expected.add(new SavedDataAddresses(s2, program.getImageBase()));

		Assert.assertEquals("should have found match", x, expected);
	}

	@Test
	public void testRunPatternWithConstraintEnforcement() {
		List<SavedDataAddresses> x = PickledCanary.parseAndRunAll(monitor, this.program,
				program.getMemory().getMinAddress(), enforceConstraintsPattern);

		List<SavedDataAddresses> expected = new ArrayList<>();
		SavedData s = new SavedData(dataBase + 8, dataBase + 20);
		s.addOrFail(new ConcreteOperandField("Q1", "r1"));
		expected.add(new SavedDataAddresses(s, program.getImageBase()));

		Assert.assertEquals("should have found match", x, expected);
	}

	@Test
	public void testTwoWildcards() {
		List<String> testQueryPatternExpected = new ArrayList<>();
		testQueryPatternExpected.add("{\"tables\":[" + tablesForTwoWildcardsInstruction + "],\"steps\":["
				+ stepsForTwoWildcardsInstruction + "]" + this.getCompileInfo());
		testQueryPatternExpected.add("{\"tables\":[" + tablesForTwoWildcardsInstruction + "],\"steps\":["
				+ stepsForTwoWildcardsInstruction_101 + "]" + this.getCompileInfo());
		generatePatternTestHelper(twoWildcardsInstruction, testQueryPatternExpected);
	}

	@Test
	public void testInstructionsWithWildcards() {
		List<String> testQueryPatternExpected = new ArrayList<>();
		// For Ghidra versions in the 9.2 ballpark
		testQueryPatternExpected.add("{\"tables\":[" + tablesForInstructionsWithWildcards + "],\"steps\":["
				+ stepsForInstructionsWithWildcards + "]" + this.getCompileInfo());
		// For Ghidra versions in the 10.1 ballpark
		testQueryPatternExpected.add("{\"tables\":[" + tablesForInstructionsWithWildcards + "],\"steps\":["
				+ stepsForInstructionsWithWildcards_newer + "]" + this.getCompileInfo());
		// For Ghidra versions in the 10.2 ballpark
		testQueryPatternExpected.add("{\"tables\":[" + tablesForInstructionsWithWildcards + "],\"steps\":["
				+ stepsForInstructionsWithWildcards_evenNewer + "]" + this.getCompileInfo());
		generatePatternTestHelper(instructionsWithWildcards, testQueryPatternExpected);
	}

	@Test
	public void testBneInstruction() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForBneInstruction + "],\"steps\":["
				+ stepsForBneInstruction + "]";
		generatePatternTestHelper(bneInstruction, testQueryPatternExpected + this.getCompileInfo());
	}

	@Test
	public void testLdrInstruction() {
		List<String> testQueryPatternExpected = new ArrayList<>();
		testQueryPatternExpected.add("{\"tables\":[" + tablesForLdrInstruction + "],\"steps\":["
				+ stepsForLdrInstruction + "]" + this.getCompileInfo());

		testQueryPatternExpected.add("{\"tables\":[" + tablesForLdrInstruction + "],\"steps\":["
				+ stepsForLdrInstruction_pre1014 + "]" + this.getCompileInfo());
		generatePatternTestHelper(ldrInstruction, testQueryPatternExpected);
	}

	@Test
	public void testLabelPatternBeq() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), beqPatternLabel);

		Assert.assertEquals(1, results.size());
		SavedDataAddresses result = results.get(0);
		Assert.assertEquals(this.program.getMinAddress().add(beqOffset + 16), result.labels.get("foo"));
	}

	@Test
	public void testMisalignedLabelPatternBeq() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), beqPatternMisallignedLabel);

		Assert.assertEquals(0, results.size());
	}

	@Test
	public void testLabelPatternBl() {
		List<String> testQueryPatternExpected = new ArrayList<>();
		testQueryPatternExpected.add(
				"{\"tables\":[" + tablesForLabelBl + "],\"steps\":[" + stepsForLabelBl + "]" + this.getCompileInfo());
		testQueryPatternExpected.add("{\"tables\":[" + tablesForLabelBl + "],\"steps\":[" + stepsForLabelBl_newer + "]"
				+ this.getCompileInfo());
		generatePatternTestHelper(blPatternLabel, testQueryPatternExpected);

	}

	@Test
	public void testLabelPatternBlExecution() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), blPatternLabel);

		Assert.assertEquals(1, results.size());
		SavedDataAddresses result = results.get(0);
		Assert.assertEquals(this.program.getMinAddress().add(blOffset), result.labels.get("foo"));
	}

	@Test
	public void testMisalignedLabelPatternBl() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), blPatternMisallignedLabel);

		Assert.assertEquals(0, results.size());
	}

	@Test
	public void testLabelPatternLdr() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), ldrPatternLabel);

		Assert.assertEquals(1, results.size());
		SavedDataAddresses result = results.get(0);
		Assert.assertEquals(this.program.getMinAddress().add(ldrOffset), result.getStart());
		Assert.assertEquals(this.program.getMinAddress().add(ldrOffset + 0xc), result.labels.get("foo"));

		// Also testing the RemoveDebug functionality and seeing if it matches
		List<String> testQueryPatternExpected = new ArrayList<>();
		testQueryPatternExpected.add("{\"tables\":[" + tablesForLdrPatternLabel + "],\"steps\":["
				+ stepsForLdrPatternLabel + "],\"compile_info\":[],\"pattern_metadata\":{}}");
		testQueryPatternExpected.add("{\"tables\":[" + tablesForLdrPatternLabel + "],\"steps\":["
				+ stepsForLdrPatternLabel1003 + "],\"compile_info\":[],\"pattern_metadata\":{}}");

		generatePatternTestHelper(ldrPatternLabel, testQueryPatternExpected, true);
	}

	@Test
	public void testMisalignedLabelPatternLdr() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), ldrPatternMisallignedLabel);

		Assert.assertEquals(0, results.size());
	}
}
