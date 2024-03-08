
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import ghidra.test.ClassicSampleX86ProgramBuilder;

public class X86LePickledCanaryTest extends PickledCanaryTest {
	// TODO: try some nasty x86 stuff with e.g. pointer arithmetic heavy lea, GAS
	// vs. Intel syntax, etc.,

	@Override
	protected String getCompileInfoRaw() {
		return ",\"compile_info\":[{\"compiled_using_binary\":[{\"path\":[\"unknown\"],\"compiled_at_address\":[\"01006420\"],\"md5\":[\"unknown\"]}],\"language_id\":[\"x86:LE:32:default\"]}],\"pattern_metadata\":{}}";
	}

	private static final String simpleInstruction = "MOV EBP,ESP";
	private static final String stepsForSimpleInstruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[139,236]},{\"operands\":[],\"value\":[137,229]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"}";

	private static final String simpleInstruction2 = "LEA EAX, [EBP + -0x6c]";
	private static final String stepsForSimpleInstruction2 = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[141,68,37,148]}],\"mask\":[255,255,63,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[141,132,37,148,255,255,255]}],\"mask\":[255,255,63,255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[141,133,148,255,255,255]}],\"mask\":[255,255,255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[141,69,148]}],\"mask\":[255,255,255]}],\"type\":\"LOOKUP\"}";

	private static final String byteInstruction = "`=0xA7`";
	private static final String stepsForByteInstruction = "{\"type\":\"BYTE\",\"value\":167}";

	private static final String byteInstruction2 = "`=0xb7`";
	private static final String stepsForByteInstruction2 = "{\"type\":\"BYTE\",\"value\":183}";

	private static final String stringInstruction = "`\"X86\"`";
	private static final String stepsForStringInstruction = "{\"type\":\"BYTE\",\"value\":88},{\"type\":\"BYTE\",\"value\":56},{\"type\":\"BYTE\",\"value\":54}";

	private static final String byteMaskInstruction = "`&0x7=0x3`";
	private static final String stepsForByteMaskInstruction = "{\"type\":\"MASKEDBYTE\",\"value\":3,\"mask\":7}";

	private static final String labelInstruction = "`foo:`";
	private static final String stepsForLabelInstruction = "{\"type\":\"LABEL\",\"value\":\"foo\"}";

	private static final String simpleWildcardInstruction = "MOV EBP, `Q1/E.P`";
	private static final String simpleWildcardAgainInstruction = "MOV EBP, `Q1/E.P`";
	private static final String stepsForSimpleWildcardInstruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,56]}],\"value\":[137,197]}],\"mask\":[255,199]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,7]}],\"value\":[139,232]}],\"mask\":[255,248]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForSimpleWildcardInstruction = "{\"EBP\":[{\"value\":[5],\"mask\":[7]}],\"ESP\":[{\"value\":[4],\"mask\":[7]}]}";

	private static final String simpleWildcardInstruction2 = "LEA EAX, [ `Q1` + -0x6c ]";
	private static final String stepsForSimpleWildcardInstruction2 = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":5,\"mask\":[0,0,7,0,0,0,0]}],\"value\":[141,132,32,148,255,255,255]}],\"mask\":[255,255,56,255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":4,\"mask\":[0,7,0]}],\"value\":[141,64,148]}],\"mask\":[255,248,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":4,\"mask\":[0,7,0,0,0,0]}],\"value\":[141,128,148,255,255,255]}],\"mask\":[255,248,255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":3,\"mask\":[0,0,0,0]}],\"value\":[103,141,68,148]},{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":2,\"mask\":[0,0,0,0]}],\"value\":[103,141,69,148]},{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,0,0,0]}],\"value\":[103,141,70,148]},{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":1,\"mask\":[0,0,0,0]}],\"value\":[103,141,71,148]}],\"mask\":[255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":5,\"mask\":[0,0,7,0]}],\"value\":[141,68,32,148]}],\"mask\":[255,255,56,255]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForSimpleWildcardInstruction2 = "{\"BP\":[{\"value\":[],\"mask\":[]}]},{\"BX\":[{\"value\":[],\"mask\":[]}]},{\"DI\":[{\"value\":[],\"mask\":[]}]},{\"SI\":[{\"value\":[],\"mask\":[]}]},{\"EBP\":[{\"value\":[5],\"mask\":[7]}],\"EDX\":[{\"value\":[2],\"mask\":[7]}],\"EBX\":[{\"value\":[3],\"mask\":[7]}],\"ESI\":[{\"value\":[6],\"mask\":[7]}],\"ECX\":[{\"value\":[1],\"mask\":[7]}],\"EDI\":[{\"value\":[7],\"mask\":[7]}],\"EAX\":[{\"value\":[0],\"mask\":[7]}]},{\"EBP\":[{\"value\":[5],\"mask\":[7]}],\"ESP\":[{\"value\":[4],\"mask\":[7]}],\"EDX\":[{\"value\":[2],\"mask\":[7]}],\"EBX\":[{\"value\":[3],\"mask\":[7]}],\"ESI\":[{\"value\":[6],\"mask\":[7]}],\"ECX\":[{\"value\":[1],\"mask\":[7]}],\"EDI\":[{\"value\":[7],\"mask\":[7]}],\"EAX\":[{\"value\":[0],\"mask\":[7]}]}";

	private static final String simpleWildcardNoDelimiter2Instruction = "SHRD EAX,EBX,`Q1[..]`";
	// The "expression" portion(s) of these steps have not been verified
	private static final String stepsForSimpleWildcardNoDelimiter2Instruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":7,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,255]}],\"value\":[15,172,216,0]}],\"mask\":[255,255,255,0]}],\"type\":\"LOOKUP\"}";

	private static final String simpleTrueWildcardInstruction = "MOV EBP,`*/E.P`";
	private static final String stepsForSimpleTrueWildcardInstruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[137,197]}],\"mask\":[255,199]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[139,232]}],\"mask\":[255,248]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForSimpleTrueWildcardInstruction = "";

	private static final String simpleScalarWildcardInstruction = "MOV EBP,`Q1[..]`";
	// The "expression" portion(s) of these steps have not been verified
	private static final String stepsForSimpleScalarWildcardInstruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":31,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":3,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,255,255,255,255]}],\"value\":[189,0,0,0,0]}],\"mask\":[255,0,0,0,0]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":31,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":3,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,255,255,255,255]}],\"value\":[199,197,0,0,0,0]}],\"mask\":[255,255,0,0,0,0]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForSimpleScalarWildcardInstruction = "";

	private static final String doubleWildcardInstruction = "MOV `Q1/E.P`,`Q1`";
	private static final String stepsForDoubleWildcardInstruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,7]},{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,56]}],\"value\":[139,192]},{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,7]},{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,56]}],\"value\":[137,192]}],\"mask\":[255,192]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForDoubleWildcardInstruction = "{\"EBP\":[{\"value\":[5],\"mask\":[7]}],\"ESP\":[{\"value\":[4],\"mask\":[7]}]}";

	private static final String negativeInstruction = "`NOT {`\n" + byteInstruction + "\n`} END_NOT`";
	private static final String stepsForNegativeInstruction = "{\"pattern\":{\"tables\":[],\"steps\":["
			+ stepsForByteInstruction
			+ ",{\"type\":\"MATCH\"}],\"pattern_metadata\":{}},\"type\":\"NEGATIVELOOKAHEAD\"}";

	private static final String anybytesInstruction = "`ANY_BYTES{4,8}`";
	private static final String stepsForAnybytesInstruction = "{\"note\":\"AnyBytesNode Start: 4 End: 8 Interval: 1 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{4,8}`\",\"min\":4,\"max\":8,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"}";

	private static final String anybytesInstructionInterval = "`ANY_BYTES{4,8,2}`";
	private static final String stepsForAnybytesInstructionInterval = "{\"note\":\"AnyBytesNode Start: 4 End: 8 Interval: 2 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{4,8,2}`\",\"min\":4,\"max\":8,\"interval\":2,\"type\":\"ANYBYTESEQUENCE\"}";

	private static final String metaInstruction = "`META`\n{\n;this comment shouldn't be included in the output\n\"foo\":\"bar\"\n}\n`META_END`\n"
			+ byteMaskInstruction;
	// Notice that this has the compile_info as well!!!
	private static final String stepsForMetaInstruction = stepsForByteMaskInstruction
			+ "],\"compile_info\":[{\"compiled_using_binary\":[{\"path\":[\"unknown\"],\"compiled_at_address\":[\"01001000\"],\"md5\":[\"unknown\"]}],\"language_id\":[\"x86:LE:32:default\"]}],\"pattern_metadata\":{\"foo\":\"bar\"}}";

	private static final String callInstruction = "CALL 0x004058f3";
	private static final String stepsForCallInstruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[232,238,72,64,255]}],\"mask\":[255,255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[103,232,237,72,64,255]}],\"mask\":[255,255,255,255,255,255]}],\"type\":\"LOOKUP\"}";

	@Before
	public void setup() throws Exception {
		// shamelessly stolen from some Ghidra integration test
		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		setup(builder);
	}

	@Test
	public void testPatternGenerator() {
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[" + stepsForSimpleInstruction + "]";

		generatePatternTestHelper(simpleInstruction, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testPatternGenerator2() {
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[" + stepsForSimpleInstruction2 + "]";
		generatePatternTestHelper(simpleInstruction2, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testComments() {
		String testQuery = "; A comment\n" + simpleInstruction + "\n      ; Another comment";
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[" + stepsForSimpleInstruction + "]";
		generatePatternTestHelper(testQuery, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testOrPattern() {
		// Notice that there are whitespace characters after START_OR (something we've
		// had trouble with in the past)
		final String testQuery = "`START_OR`    \n" + simpleInstruction + "\n`OR`\n" + simpleInstruction
				+ "\n`END_OR`\n";
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[{\"dest2\":3,\"type\":\"SPLIT\",\"dest1\":1},"
				+ stepsForSimpleInstruction + ",{\"type\":\"JMP\",\"dest\":4}," + stepsForSimpleInstruction + "]";
		generatePatternTestHelper(testQuery, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testOrPatternWithBytes() {
		final String testQuery = "`START_OR`\n" + byteInstruction + "\n`OR`   \n" + byteMaskInstruction
				+ "\n`END_OR`\n";
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[{\"dest2\":3,\"type\":\"SPLIT\",\"dest1\":1},"
				+ stepsForByteInstruction + ",{\"type\":\"JMP\",\"dest\":4}," + stepsForByteMaskInstruction + "]";
		generatePatternTestHelper(testQuery, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testMultiOrPatternWithBytes() {
		final String testQuery = "`START_OR`\n" + byteInstruction + "\n`OR`   \n" + byteInstruction2 + "\n`OR`   \n"
				+ byteMaskInstruction + "\n`END_OR`\n";
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[{\"dests\":[1,3,5],\"type\":\"SPLITMULTI\"},"
				+ stepsForByteInstruction + ",{\"type\":\"JMP\",\"dest\":6}," + stepsForByteInstruction2
				+ ",{\"type\":\"JMP\",\"dest\":6}," + stepsForByteMaskInstruction + "]";
		generatePatternTestHelper(testQuery, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testPatternWithStringAndOr() {
		final String testQuery = "`START_OR`\n" + stringInstruction + "\n`OR`   \n" + byteMaskInstruction
				+ "\n`END_OR`\n";
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[{\"dest2\":5,\"type\":\"SPLIT\",\"dest1\":1},"
				+ stepsForStringInstruction + ",{\"type\":\"JMP\",\"dest\":6}," + stepsForByteMaskInstruction + "]";
		generatePatternTestHelper(testQuery, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testPatternWithWildcard() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForSimpleWildcardInstruction + "],\"steps\":["
				+ stepsForSimpleWildcardInstruction + "]";
		generatePatternTestHelper(simpleWildcardInstruction, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testPatternWithWildcard2() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForSimpleWildcardInstruction2 + "],\"steps\":["
				+ stepsForSimpleWildcardInstruction2 + "]";
		generatePatternTestHelper(simpleWildcardInstruction2, testQueryPatternExpected + getCompileInfo());
	}

	// This works... but it's slow... commenting out for now
	private static final String simpleWildcardNoDelimiterInstruction = "MOV EBP,`Q1[..]`";
	// The "expression" portion(s) of these steps have not been verified
	private static final String stepsForSimpleWildcardNoDelimiterInstruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":31,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":3,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,255,255,255,255]}],\"value\":[189,0,0,0,0]}],\"mask\":[255,0,0,0,0]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":31,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":3,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,255,255,255,255]}],\"value\":[199,197,0,0,0,0]}],\"mask\":[255,255,0,0,0,0]}],\"type\":\"LOOKUP\"}";

	@Test
	public void testPatternWithWildcardNoDelim() {
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[" + stepsForSimpleWildcardNoDelimiterInstruction
				+ "]";
		generatePatternTestHelper(simpleWildcardNoDelimiterInstruction, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testPatternWithWildcardNoDelim2() {
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[" + stepsForSimpleWildcardNoDelimiter2Instruction
				+ "]";
		generatePatternTestHelper(simpleWildcardNoDelimiter2Instruction, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testPatternWithTrueWildcard() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForSimpleTrueWildcardInstruction + "],\"steps\":["
				+ stepsForSimpleTrueWildcardInstruction + "]";
		generatePatternTestHelper(simpleTrueWildcardInstruction, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testPatternWithScalarWildcard() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForSimpleScalarWildcardInstruction + "],\"steps\":["
				+ stepsForSimpleScalarWildcardInstruction + "]";
		generatePatternTestHelper(simpleScalarWildcardInstruction, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testPatternDoubleWildcard() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForDoubleWildcardInstruction + "],\"steps\":["
				+ stepsForDoubleWildcardInstruction + "]";
		generatePatternTestHelper(doubleWildcardInstruction, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testPatternWithNegative() {
		final String testQuery = byteInstruction + "\n" + negativeInstruction + "\n" + byteMaskInstruction;
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[" + stepsForByteInstruction + ","
				+ stepsForNegativeInstruction + "," + stepsForByteMaskInstruction + "]";
		generatePatternTestHelper(testQuery, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testPatternWithAnyBytes() {
		final String testQuery = byteInstruction + "\n" + anybytesInstruction + "\n" + byteMaskInstruction;
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[" + stepsForByteInstruction + ","
				+ stepsForAnybytesInstruction + "," + stepsForByteMaskInstruction + "]";
		generatePatternTestHelper(testQuery, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testPatternWithAnyBytesInterval() {
		final String testQuery = byteInstruction + "\n" + anybytesInstructionInterval + "\n" + byteMaskInstruction;
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[" + stepsForByteInstruction + ","
				+ stepsForAnybytesInstructionInterval + "," + stepsForByteMaskInstruction + "]";
		generatePatternTestHelper(testQuery, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testPatternWithMeta() {
		final String testQuery = metaInstruction;
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[" + stepsForMetaInstruction;
		generatePatternTestHelper(testQuery, testQueryPatternExpected);
	}

	@SuppressWarnings("deprecation")
	@Rule
	public final ExpectedException exceptionRule = ExpectedException.none();

	@Test
	public void testInvalidInstruction() {
		final String testQuery = "XXXXX";
		exceptionRule.expect(RuntimeException.class);
		exceptionRule.expectMessage("An assembly instruction in your pattern (" + testQuery
				+ ") did not return any output. Make sure your assembly instructions are valid or that you are using a binary with the same architecture.");
		generatePatternTestHelper(testQuery, "");
	}

	@Test
	public void testPatternWithWildcardAgain() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForSimpleWildcardInstruction + "],\"steps\":["
				+ stepsForSimpleWildcardInstruction + "," + stepsForSimpleWildcardInstruction + "]";
		generatePatternTestHelper(simpleWildcardInstruction + "\n" + simpleWildcardAgainInstruction,
				testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testTwoStartMeta() {
		exceptionRule.expect(RuntimeException.class);
		exceptionRule.expectMessage("Pattern lexer encountered error when processing line 6:1 token recognition error at: 'META`'");
		final String testQuery = ";something\n`META`\n{\"foo\":\"bar\"\n}\n`META`\n`META`";
		generatePatternTestHelper(testQuery, "");
	}

	@Test
	public void testTwoMetaBlocks() {
		exceptionRule.expect(RuntimeException.class);
		exceptionRule.expectMessage("Can not have more than one META section!");
		final String testQuery = ";something\n`META`\n{\"foo\":\"bar\"\n}\n`META_END`\n`META`\n{\"baz\":\"bop\"\n}\n`META_END`";
		generatePatternTestHelper(testQuery, "");
	}

	@Test
	public void testTwoEndMeta() {
		exceptionRule.expect(RuntimeException.class);
		exceptionRule.expectMessage("Pattern lexer encountered error when processing line 7:1 token recognition error at: 'META_END`'");
		final String testQuery = ";something\n`META`\n{\n\"foo\":\"bar\"\n}\n`META_END`\n`META_END`";
		generatePatternTestHelper(testQuery, "");
	}

	@Test
	public void testEndMetaBeforeMeta() {
		exceptionRule.expect(RuntimeException.class);
		exceptionRule.expectMessage("Pattern lexer encountered error when processing line 1:1 token recognition error at: 'META_END`'");
		final String testQuery = "`META_END`\n;something\n`META`\n{\n\"foo\":\"bar\"\n}\n`META_END`\n";
		generatePatternTestHelper(testQuery, "");
	}

	@Test
	public void testEmptyCommand() {
		exceptionRule.expect(RuntimeException.class);
		exceptionRule.expectMessage("Pattern lexer encountered error when processing line 2:1 mismatched input '`' expecting {'=', '&', ANY_BYTES, LABEL, BYTE_STRING}");
		final String testQuery = ";something\n``";
		generatePatternTestHelper(testQuery, "");
	}

	@Test
	public void testUnbalancedCommand() {
		exceptionRule.expect(RuntimeException.class);
		exceptionRule.expectMessage("This line doesn't have a balanced number of '`' characters and didn't assemble to any instruction. Check this line: 'MOV `'");
		final String testQuery = ";something\nMOV `\n;foo";
		generatePatternTestHelper(testQuery, "");
	}

	@Test
	public void testPatternWithLabel() {
		final String testQuery = byteInstruction + "\n" + anybytesInstruction + "\n" + labelInstruction + "\n"
				+ byteMaskInstruction;
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[" + stepsForByteInstruction + ","
				+ stepsForAnybytesInstruction + "," + stepsForLabelInstruction + "," + stepsForByteMaskInstruction
				+ "]";
		generatePatternTestHelper(testQuery, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testCallInstruction() {
		// makes sure shifts aren't double counted in backfills
		final String testQuery = callInstruction;
		String testQueryPatternExpected = "{\"tables\":[],\"steps\":[" + stepsForCallInstruction + "]";
		generatePatternTestHelper(testQuery, testQueryPatternExpected + getCompileInfo());
	}
}
