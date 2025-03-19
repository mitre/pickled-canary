// Copyright (C) 2025 The MITRE Corporation All Rights Reserved
package org.mitre.pickledcanary.headless;

import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.patterngenerator.QueryParseException;
import org.mitre.pickledcanary.search.SavedDataAddresses;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.database.ProgramBuilder;

public class ContextTest extends PickledCanaryTest {

	@Override
	protected String getCompileInfoRaw() {
		return ",\"compile_info\":[{\"compiled_using_binary\":[{\"path\":[\"unknown\"],\"compiled_at_address\":[\"00000000\"],\"md5\":[\"unknown\"]}],\"language_id\":[\"ctxtest:LE:16:default\"]}],\"pattern_metadata\":{}}";
	}

	private static final String emptyTable = "";

	private static final String ambiguousContextPattern =
			"Add R1, `Q1`\r\n"
			+ "Shift R1, R1";
	private static final String tablesForAmbiguousContextPattern = "{\"R2\":[{\"value\":[1],\"mask\":[15]}],\"R3\":[{\"value\":[2],\"mask\":[15]}],\"R4\":[{\"value\":[3],\"mask\":[15]}],\"R1\":[{\"value\":[0],\"mask\":[15]}]}";
	private static final String stepsForAmbiguousContextPattern = "{\"dest2\":4,\"type\":\"SPLIT\",\"dest1\":1},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,17]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":6},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,18]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"}";

	private static final String contextBasedBranchPattern =
			"BranchC `:Q1`\r\n"
			+ "`ANY_BYTES{0,4}`\r\n"
			+ "`Q1:`\r\n"
			+ "Add R1, R1";
	private static final String stepsForContextBasedBranchPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Mult\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":true,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":2}}},\"right\":{\"op\":\"ContextField\",\"value\":{\"bitend\":31,\"shift\":0,\"signbit\":false,\"bitstart\":28,\"byteend\":3,\"bytestart\":3}}}},\"right\":{\"op\":\"EndInstructionValue\"}}},\"var_id\":\":Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"context\":[2,0],\"value\":[0,14]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 0 End: 4 Interval: 1 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{0,4}`\",\"min\":0,\"max\":4,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"},{\"type\":\"LABEL\",\"value\":\"Q1\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"}";

	private static final String contextValidityPattern =
			"Set\r\n"
			+ "Unset\r\n"
			+ "Set\r\n"
			+ "Unset";
	private static final String stepsForContextValidityPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,15]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,16]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,15]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,16]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"}";

	private static final String contextAnnotationPattern =
			"Shift R1, R1\r\n"
			+ "`CONTEXT\r\n"
			+ "set = 1\r\n"
			+ "`\r\n"
			+ "`ANY_BYTES{2,2}`\r\n"
			+ "Shift R1, R1";
	private static final String stepsForContextAnnotationPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,17]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 2 End: 2 Interval: 1 From: Token from line #5: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{2,2}`\",\"min\":2,\"max\":2,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,18]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"}";

	private static final String noflowContextPattern =
			"Extend\r\n"
			+ "LoadE R1, 0xaaaa\r\n"
			+ "Extend\r\n"
			+ "LoadE R1, 0xbbbb";
	private static final String stepsForNoflowContextPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,19]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,20,170,170]}],\"mask\":[240,255,255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,19]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,20,187,187]}],\"mask\":[240,255,255,255]}],\"type\":\"LOOKUP\"}";

	private static final String oneEncodingNoflowPattern =
			"ExtendX\r\n"
			+ "LoadX R1, 0xaaaa";
	private static final String stepsForOneEncodingNoflowPattern = "{\"dest2\":4,\"type\":\"SPLIT\",\"dest1\":1},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,24]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,27,170,170]}],\"mask\":[240,255,255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":6},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,25]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,26,170,170]}],\"mask\":[240,255,255,255]}],\"type\":\"LOOKUP\"}";

	private static final String noflowOrBlockPattern =
			"Extend\r\n"
			+ "`START_OR`\r\n"
			+ "Alloc 0x1\r\n"
			+ "`OR`\r\n"
			+ "LoadE R1, 0xaaaa\r\n"
			+ "Extend\r\n"
			+ "Alloc 0x0\r\n"
			+ "`END_OR`";
	private static final String stepsForNoflowOrBlockPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,19]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"dest2\":4,\"type\":\"SPLIT\",\"dest1\":2},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":7},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,20,170,170]}],\"mask\":[240,255,255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,19]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"}";

	private static final String illegalNoFlowContextPattern =
			"Extend\r\n"
			+ "`START_OR`"
			+ "LoadE R1, 0xaaaa\r\n"
			+ "`OR`"
			+ "Extend\r\n"
			+ "LoadE R1 0xaaaa\r\n"
			+ "`END_OR";

	private static final String illegalNoFlowContext2Pattern =
			"Extend\r\n"
			+ "`START_OR`"
			+ "LoadE R1, 0xaaaa\r\n"
			+ "`OR`"
			+ "LoadE R1 0xaaaa\r\n"
			+ "LoadE R1 0xaaaa\r\n"
			+ "`END_OR";

	private static final String tablesForOrPatterns = "{\"R2\":[{\"value\":[1],\"mask\":[15]}],\"R3\":[{\"value\":[2],\"mask\":[15]}],\"R4\":[{\"value\":[3],\"mask\":[15]}],\"R1\":[{\"value\":[0],\"mask\":[15]}]}";
	private static final String stepsForLastInstructionContext2Pattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,7]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,8]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"}";
	private static final String lastInstructionContext2Pattern =
			"Add R1,R2\r\n"
			+ "Not R1";

	private static final String stepsForLastInstructionContext3Pattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,9]},{\"operands\":[],\"value\":[1,11]},{\"operands\":[],\"value\":[16,10]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"}";
	private static final String lastInstructionContext3Pattern =
			"Add R1,R2\r\n"
			+ "And R1,R2";

	private static final String stepsForLastInstructionContext2WildcardPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]},{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"}";
	private static final String lastInstructionContext2WildcardPattern =
			"Add R1,R2\r\n"
			+ "Add R1,`Q1`";

	private static final String stepsForLastInstructionContext3WildcardPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,9]},{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,11]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[240,0]}],\"value\":[0,10]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"}";
	private static final String lastInstructionContext3WildcardPattern =
			"Add R1,R2\r\n"
			+ "And R1,`Q1`";

	//
	private static final String stepsForDedupNoOrContext2Pattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,7]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,8]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,7]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,8]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"}";
	private static final String dedupNoOrContext2Pattern =
			"Add R1,R2\r\n"
			+ "Not R1\r\n"
			+ "Mov R2,R4\r\n"
			+ "Not R2\r\n"
			+ "Alloc 0";

	private static final String stepsForDedupNoOrContext3Pattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,9]},{\"operands\":[],\"value\":[1,11]},{\"operands\":[],\"value\":[16,10]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,9]},{\"operands\":[],\"value\":[1,11]},{\"operands\":[],\"value\":[16,10]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"}";
	private static final String dedupNoOrContext3Pattern =
			"Add R1,R2\r\n"
			+ "And R1,R2\r\n"
			+ "Mov R2,R4\r\n"
			+ "And R1,R2\r\n"
			+ "Alloc 0";

	private static final String stepsForDedupNoOrWildcardContext2Pattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]},{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]},{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q2\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"}";
	private static final String dedupNoOrWildcardContext2Pattern =
			"Add R1,R2\r\n"
			+ "Add R1,`Q1`\r\n"
			+ "Mov R2,R4\r\n"
			+ "Add R1,`Q2`\r\n"
			+ "Alloc 0";

	private static final String stepsForDedupNoOrWildcardContext3Pattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,9]},{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,11]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[240,0]}],\"value\":[0,10]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,9]},{\"operands\":[{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,11]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[240,0]}],\"value\":[0,10]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"}";
	private static final String dedupNoOrWildcardContext3Pattern =
			"Add R1,R2\r\n"
			+ "And R1,`Q1`\r\n"
			+ "Mov R2,R4\r\n"
			+ "And R1,`Q2`\r\n"
			+ "Alloc 0";

	private static final String stepsForDedupOr2Context2OutPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,7]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,8]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"dest2\":5,\"type\":\"SPLIT\",\"dest1\":2},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":7},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":3}";
	private static final String dedupOr2Context2OutPattern =
			"Not R1\r\n"
			+ "`START_OR`\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`END_OR`\r\n"
			+ "Mov R1,R3";

	private static final String stepsForDedupOr2Context3OutPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,9]},{\"operands\":[],\"value\":[1,11]},{\"operands\":[],\"value\":[16,10]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dest2\":5,\"type\":\"SPLIT\",\"dest1\":2},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":7},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":3}";
	private static final String dedupOr2Context3OutPattern =
			"And R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`END_OR`\r\n"
			+ "Mov R1,R3";

	private static final String stepsForDedupOr2WildcardContext2OutPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]},{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dest2\":5,\"type\":\"SPLIT\",\"dest1\":2},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":7},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":3}";
	private static final String dedupOr2WildcardContext2OutPattern =
			"Add R1,`Q1`\r\n"
			+ "`START_OR`\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`END_OR`\r\n"
			+ "Mov R1,R3";

	private static final String stepsForDedupOr2WildcardContext3OutPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,9]},{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,11]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[240,0]}],\"value\":[0,10]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"dest2\":5,\"type\":\"SPLIT\",\"dest1\":2},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":7},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":3}";
	private static final String dedupOr2WildcardContext3OutPattern =
			"And R1,`Q1`\r\n"
			+ "`START_OR`\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`END_OR`\r\n"
			+ "Mov R1,R3";

	private static final String stepsForDedupOr3Context2OutPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,7]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,8]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,5,7],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":9},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":3},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":3}";
	private static final String dedupOr3Context2OutPattern =
			"Not R1\r\n"
			+ "`START_OR`\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForDedupOr3Context3OutPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,9]},{\"operands\":[],\"value\":[1,11]},{\"operands\":[],\"value\":[16,10]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,5,7],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":9},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":3},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":3}";
	private static final String dedupOr3Context3OutPattern =
			"And R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForDedupOr3WildcardContext2OutPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]},{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,5,7],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":9},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":3},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":3}";
	private static final String dedupOr3WildcardContext2OutPattern =
			"Add R1,`Q1`\r\n"
			+ "`START_OR`\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForDedupOr3WildcardContext3OutPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,9]},{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,11]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[240,0]}],\"value\":[0,10]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,5,7],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":9},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":3},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":3}";
	private static final String dedupOr3WildcardContext3OutPattern =
			"And R1,`Q1`\r\n"
			+ "`START_OR`\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForDedupOr2Context2InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":2},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,7]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,8]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":8},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String dedupOr2Context2InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "Not R1\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForDedupOr2Context3InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":2},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,9]},{\"operands\":[],\"value\":[1,11]},{\"operands\":[],\"value\":[16,10]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":8},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String dedupOr2Context3InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "And R1,R2\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForDedupOr2WildcardContext2InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":2},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]},{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":8},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String dedupOr2WildcardContext2InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "Add R1,`Q1`\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForDedupOr2WildcardContext3InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":2},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,9]},{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,11]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[240,0]}],\"value\":[0,10]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":8},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String dedupOr2WildcardContext3InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "And R1,`Q1`\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForDedupOr3Context2InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,6,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,7]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,8]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":10},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String dedupOr3Context2InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "Not R1\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForDedupOr3Context3InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,6,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,9]},{\"operands\":[],\"value\":[1,11]},{\"operands\":[],\"value\":[16,10]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":10},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String dedupOr3Context3InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "And R1,R2\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForDedupOr3WildcardContext2InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,6,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]},{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":10},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String dedupOr3WildcardContext2InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "Add R1,`Q1`\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForDedupOr3WildcardContext3InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,6,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,9]},{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,11]}],\"mask\":[240,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[240,0]}],\"value\":[0,10]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[19,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":10},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String dedupOr3WildcardContext3InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "And R1,`Q1`\r\n"
			+ "Mov R2,R4\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForNoOrContext2Pattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dest2\":11,\"type\":\"SPLIT\",\"dest1\":2},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,7]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dest2\":8,\"type\":\"SPLIT\",\"dest1\":5},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,7]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":14},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,8]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":14},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,8]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dest2\":8,\"type\":\"SPLIT\",\"dest1\":5}";
	private static final String noOrContext2Pattern =
			"Add R1,R2\r\n"
			+ "Not R1\r\n"
			+ "Truncate R1\r\n"
			+ "Not R2\r\n"
			+ "Truncate R2";

	private static final String stepsForNoOrContext3Pattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,14,17],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,9]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dests\":[5,8,11],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[35,9]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":20},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[50,10]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":20},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[35,11]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":20},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,10]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dests\":[5,8,11],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,11]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dests\":[5,8,11],\"type\":\"SPLITMULTI\"}";
	private static final String noOrContext3Pattern =
			"Add R1,R2\r\n"
			+ "And R1,R2\r\n"
			+ "Truncate R1\r\n"
			+ "And R3,R4\r\n"
			+ "Truncate R2";

	private static final String stepsForNoOrWildcardContext2Pattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dest2\":11,\"type\":\"SPLIT\",\"dest1\":2},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,17]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dest2\":8,\"type\":\"SPLIT\",\"dest1\":5},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[17,17]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":14},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q2\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[17,18]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":14},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,18]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dest2\":8,\"type\":\"SPLIT\",\"dest1\":5}";
	private static final String noOrWildcardContext2Pattern =
			"Add R1,R2\r\n"
			+ "Add R1,`Q1`\r\n"
			+ "Shift R1,R1\r\n"
			+ "Add R1,`Q2`\r\n"
			+ "Shift R2,R2";

	private static final String stepsForNoOrWildcardContext3Pattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,14,17],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,9]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dests\":[5,8,11],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,9]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":20},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[240,0]}],\"value\":[0,10]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":20},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,11]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":20},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[240,0]}],\"value\":[0,10]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dests\":[5,8,11],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,11]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dests\":[5,8,11],\"type\":\"SPLITMULTI\"}";
	private static final String noOrWildcardContext3Pattern =
			"Add R1,R2\r\n"
			+ "And R1,`Q1`\r\n"
			+ "Truncate R1\r\n"
			+ "And R1,`Q2`\r\n"
			+ "Truncate R2";

	private static final String stepsForOr2Context2OutPattern = "{\"dest2\":8,\"type\":\"SPLIT\",\"dest1\":1},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,7]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":3},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":12},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,8]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":10},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or2Context2OutPattern =
			"Not R1\r\n"
			+ "`START_OR`\r\n"
			+ "Truncate R1\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`END_OR`\r\n"
			+ "Mov R1,R3";

	private static final String stepsForOr2Context3OutPattern = "{\"dests\":[1,8,12],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,9]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":3},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":16},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,10]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":10},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,11]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":14},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or2Context3OutPattern =
			"And R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "Truncate R1\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`END_OR`\r\n"
			+ "Mov R1,R3";

	private static final String stepsForOr2WildcardContext2OutPattern = "{\"dest2\":8,\"type\":\"SPLIT\",\"dest1\":1},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":3},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,17]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":12},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":10},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,18]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or2WildcardContext2OutPattern =
			"Add R1,`Q1`\r\n"
			+ "`START_OR`\r\n"
			+ "Shift R1,R1\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`END_OR`\r\n"
			+ "Mov R1,R3";

	private static final String stepsForOr2WildcardContext3OutPattern = "{\"dests\":[1,8,12],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,9]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":3},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":16},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[240,0]}],\"value\":[0,10]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":10},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,11]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dest2\":6,\"type\":\"SPLIT\",\"dest1\":14},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or2WildcardContext3OutPattern =
			"And R1,`Q1`\r\n"
			+ "`START_OR`\r\n"
			+ "Truncate R1\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`END_OR`\r\n"
			+ "Mov R1,R3";

	private static final String stepsForOr3Context2OutPattern = "{\"dest2\":10,\"type\":\"SPLIT\",\"dest1\":1},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,7]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dests\":[3,6,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":16},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,8]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"dests\":[12,14,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or3Context2OutPattern =
			"Not R1\r\n"
			+ "`START_OR`\r\n"
			+ "Truncate R1\r\n"
			+ "`OR`\r\n"
			+ "Truncate R2\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForOr3Context3OutPattern = "{\"dests\":[1,10,16],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,9]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[3,6,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":22},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,10]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[12,14,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,11]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[18,20,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or3Context3OutPattern =
			"And R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "Truncate R1\r\n"
			+ "`OR`\r\n"
			+ "Truncate R2\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForOr3WildcardContext2OutPattern = "{\"dest2\":10,\"type\":\"SPLIT\",\"dest1\":1},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dests\":[3,6,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,17]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":16},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[17,17]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dests\":[12,14,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,18]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[17,18]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or3WildcardContext2OutPattern =
			"Add R1,`Q1`\r\n"
			+ "`START_OR`\r\n"
			+ "Shift R1,R1\r\n"
			+ "`OR`\r\n"
			+ "Shift R2,R2\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForOr3WildcardContext3OutPattern = "{\"dests\":[1,10,16],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,9]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dests\":[3,6,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":22},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[240,0]}],\"value\":[0,10]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"dests\":[12,14,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,11]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dests\":[18,20,8],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or3WildcardContext3OutPattern =
			"And R1,`Q1`\r\n"
			+ "`START_OR`\r\n"
			+ "Truncate R1\r\n"
			+ "`OR`\r\n"
			+ "Truncate R2\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForOr2Context2InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,6,9],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,7]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":11},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,8]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or2Context2InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "Not R1\r\n"
			+ "Truncate R1\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForOr2Context3InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,6,9,12],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,9]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":14},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,10]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,11]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or2Context3InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "And R1,R2\r\n"
			+ "Truncate R1\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForOr2WildcardContext2InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,6,9],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,17]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":11},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,18]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or2WildcardContext2InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "Add R1,`Q1`\r\n"
			+ "Shift R1,R1\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForOr2WildcardContext3InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,6,9,12],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,9]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":14},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[240,0]}],\"value\":[0,10]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,11]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or2WildcardContext3InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "And R1,`Q1`\r\n"
			+ "Truncate R1\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForOr3Context2InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,6,9,11],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,7]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":13},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,8]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or3Context2InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "Not R1\r\n"
			+ "Truncate R1\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForOr3Context3InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,6,9,12,14],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,9]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":16},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[16,10]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,11]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or3Context3InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "And R1,R2\r\n"
			+ "Truncate R1\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForOr3WildcardContext2InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,6,9,11],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,17]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":13},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,18]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or3WildcardContext2InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "Add R1,`Q1`\r\n"
			+ "Shift R1,R1\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	private static final String stepsForOr3WildcardContext3InPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[1,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"dests\":[2,6,9,12,14],\"type\":\"SPLITMULTI\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,9]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,21]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[18,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":16},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[240,0]}],\"value\":[0,10]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,22]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,11]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,23]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,0]}],\"mask\":[15,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[2,6]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":4}";
	private static final String or3WildcardContext3InPattern =
			"Add R1,R2\r\n"
			+ "`START_OR`\r\n"
			+ "And R1,`Q1`\r\n"
			+ "Truncate R1\r\n"
			+ "`OR`\r\n"
			+ "Alloc 0\r\n"
			+ "`OR`\r\n"
			+ "Mov R1,R3\r\n"
			+ "`END_OR`\r\n"
			+ "Add R2,R3";

	@Before
	public void setUp() throws Exception {
		SleighLanguage dummy = SleighTestUtils.lazyLanguage(SleighTestUtils.getSleighResource("ctxtest.ldefs"));
		ProgramBuilder builder = new ProgramBuilder("context_test", dummy);

		builder.setBytes("0x00000000", "00 0C"); // Add R1, R1
		builder.setBytes("0x00000002", "00 11"); // Shift R1, R1
		builder.setBytes("0x00000004", "00 0D"); // Add R1, 0x0
		builder.setBytes("0x00000006", "00 12"); // Shift R1, R1

		builder.setBytes("0x00000008", "00 0E"); // BranchC 0xC
		builder.setBytes("0x0000000A", "00 11"); // Shift R1, R1
		builder.setBytes("0x0000000C", "00 0C"); // Add R1, R1

		builder.setBytes("0x0000000E", "00 0F"); // Set
		builder.setBytes("0x00000010", "00 10"); // Unset
		builder.setBytes("0x00000012", "00 0F"); // Set
		builder.setBytes("0x00000014", "00 10"); // Unset

		builder.setBytes("0x00000016", "00 11"); // Shift R1, R1
		builder.setBytes("0x00000018", "00 0F"); // Set
		builder.setBytes("0x0000001A", "00 12"); // Shift R1, R1

		builder.setBytes("0x0000001C", "00 13"); // Extend
		builder.setBytes("0x0000001E", "00 14 AA AA"); // LoadE R1, 0xaaaa
		builder.setBytes("0x00000022", "00 13"); // Extend
		builder.setBytes("0x00000024", "00 14 BB BB"); // LoadE R1, 0xbbbb

		program = builder.getProgram();
	}

	// Compile tests
	@Test
	public void testCompileAmbiguousContextPattern() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForAmbiguousContextPattern + "],\"steps\":["
				+ stepsForAmbiguousContextPattern + "]";
		generatePatternTestHelper(ambiguousContextPattern, testQueryPatternExpected + this.getCompileInfo());
	}

	@Test
	public void testCompileContextBasedBranchPattern() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForContextBasedBranchPattern + "]";
		generatePatternTestHelper(contextBasedBranchPattern, testQueryPatternExpected + this.getCompileInfo(this.program.getMinAddress().add(8)), this.program.getMinAddress().add(8));
	}

	@Test
	public void testCompileContextValidityPattern() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForContextValidityPattern + "]";
		generatePatternTestHelper(contextValidityPattern, testQueryPatternExpected + this.getCompileInfo());
	}

	@Test
	public void testCompileContextAnnotationPattern() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForContextAnnotationPattern + "]";
		generatePatternTestHelper(contextAnnotationPattern, testQueryPatternExpected + this.getCompileInfo());
	}

	@Test
	public void testCompileNoflowContextPattern() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForNoflowContextPattern + "]";
		generatePatternTestHelper(noflowContextPattern, testQueryPatternExpected + this.getCompileInfo());
	}

	// ExtendX instruction generates 2 encodings; one produces a noflow context while the other does not change context
	@Test
	public void testCompileOneEncodingNoflowPattern() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForOneEncodingNoflowPattern + "]";
		generatePatternTestHelper(oneEncodingNoflowPattern, testQueryPatternExpected + this.getCompileInfo());
	}

	@Test
	public void testCompileNoflowOrBlockPattern() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForNoflowOrBlockPattern + "]";
		generatePatternTestHelper(noflowOrBlockPattern, testQueryPatternExpected + this.getCompileInfo());
	}

	@Test (expected=QueryParseException.class)
	public void testIllegalNoFlowContextPattern() {
		generatePatternTestHelper(illegalNoFlowContextPattern, "");
	}

	@Test (expected=QueryParseException.class)
	public void testIllegalNoFlowContext2Pattern() {
		generatePatternTestHelper(illegalNoFlowContext2Pattern, "");
	}

	// The 4 tests below tests that a pattern that ends with an instruction that produces a context
	// split will end with just the instruction and nothing else; i.e. no splits
	@Test
	public void testCompileLastInstructionContext2() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForLastInstructionContext2Pattern + "]";
		generatePatternTestHelper(lastInstructionContext2Pattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileLastInstructionContext3() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForLastInstructionContext3Pattern + "]";
		generatePatternTestHelper(lastInstructionContext3Pattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileLastInstructionContext2Wildcard() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForLastInstructionContext2WildcardPattern + "]";
		generatePatternTestHelper(lastInstructionContext2WildcardPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileLastInstructionContext3Wildcard() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForLastInstructionContext3WildcardPattern + "]";
		generatePatternTestHelper(lastInstructionContext3WildcardPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	// The 20 tests below were the original tests to test context branching. However, when
	// deduplication was added, these patterns deduplicated and no longer branched, so they are now
	// the tests for deduplication.
	@Test
	public void testCompileDedupNoOrContext2() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForDedupNoOrContext2Pattern + "]";
		generatePatternTestHelper(dedupNoOrContext2Pattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupNoOrContext3() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForDedupNoOrContext3Pattern + "]";
		generatePatternTestHelper(dedupNoOrContext3Pattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupNoOrWildcardContext2() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForDedupNoOrWildcardContext2Pattern + "]";
		generatePatternTestHelper(dedupNoOrWildcardContext2Pattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupNoOrWildcardContext3() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForDedupNoOrWildcardContext3Pattern + "]";
		generatePatternTestHelper(dedupNoOrWildcardContext3Pattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr2Context2Out() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForDedupOr2Context2OutPattern + "]";
		generatePatternTestHelper(dedupOr2Context2OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr2Context3Out() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForDedupOr2Context3OutPattern + "]";
		generatePatternTestHelper(dedupOr2Context3OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr2WildcardContext2Out() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForDedupOr2WildcardContext2OutPattern + "]";
		generatePatternTestHelper(dedupOr2WildcardContext2OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr2WildcardContext3Out() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForDedupOr2WildcardContext3OutPattern + "]";
		generatePatternTestHelper(dedupOr2WildcardContext3OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr3Context2Out() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForDedupOr3Context2OutPattern + "]";
		generatePatternTestHelper(dedupOr3Context2OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr3Context3Out() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForDedupOr3Context3OutPattern + "]";
		generatePatternTestHelper(dedupOr3Context3OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr3WildcardContext2Out() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForDedupOr3WildcardContext2OutPattern + "]";
		generatePatternTestHelper(dedupOr3WildcardContext2OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr3WildcardContext3Out() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForDedupOr3WildcardContext3OutPattern + "]";
		generatePatternTestHelper(dedupOr3WildcardContext3OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr2Context2In() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForDedupOr2Context2InPattern + "]";
		generatePatternTestHelper(dedupOr2Context2InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr2Context3In() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForDedupOr2Context3InPattern + "]";
		generatePatternTestHelper(dedupOr2Context3InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr2WildcardContext2In() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForDedupOr2WildcardContext2InPattern + "]";
		generatePatternTestHelper(dedupOr2WildcardContext2InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr2WildcardContext3In() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForDedupOr2WildcardContext3InPattern + "]";
		generatePatternTestHelper(dedupOr2WildcardContext3InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr3Context2In() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForDedupOr3Context2InPattern + "]";
		generatePatternTestHelper(dedupOr3Context2InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr3Context3In() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForDedupOr3Context3InPattern + "]";
		generatePatternTestHelper(dedupOr3Context3InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr3WildcardContext2In() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForDedupOr3WildcardContext2InPattern + "]";
		generatePatternTestHelper(dedupOr3WildcardContext2InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileDedupOr3WildcardContext3In() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForDedupOr3WildcardContext3InPattern + "]";
		generatePatternTestHelper(dedupOr3WildcardContext3InPattern, testQueryPatternExpected + this.getCompileInfo());
	}

	// The 20 tests below tests context branching with combinations of OR blocks, instructions that
	// produce multiple contexts, and wildcards.
	@Test
	public void testCompileNoOrContext2() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForNoOrContext2Pattern + "]";
		generatePatternTestHelper(noOrContext2Pattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileNoOrContext3() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForNoOrContext3Pattern + "]";
		generatePatternTestHelper(noOrContext3Pattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileNoOrWildcardContext2() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForNoOrWildcardContext2Pattern + "]";
		generatePatternTestHelper(noOrWildcardContext2Pattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileNoOrWildcardContext3() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForNoOrWildcardContext3Pattern + "]";
		generatePatternTestHelper(noOrWildcardContext3Pattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr2Context2Out() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForOr2Context2OutPattern + "]";
		generatePatternTestHelper(or2Context2OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr2Context3Out() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForOr2Context3OutPattern + "]";
		generatePatternTestHelper(or2Context3OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr2WildcardContext2Out() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForOr2WildcardContext2OutPattern + "]";
		generatePatternTestHelper(or2WildcardContext2OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr2WildcardContext3Out() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForOr2WildcardContext3OutPattern + "]";
		generatePatternTestHelper(or2WildcardContext3OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr3Context2Out() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForOr3Context2OutPattern + "]";
		generatePatternTestHelper(or3Context2OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr3Context3Out() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForOr3Context3OutPattern + "]";
		generatePatternTestHelper(or3Context3OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr3WildcardContext2Out() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForOr3WildcardContext2OutPattern + "]";
		generatePatternTestHelper(or3WildcardContext2OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr3WildcardContext3Out() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForOr3WildcardContext3OutPattern + "]";
		generatePatternTestHelper(or3WildcardContext3OutPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr2Context2In() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForOr2Context2InPattern + "]";
		generatePatternTestHelper(or2Context2InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr2Context3In() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForOr2Context3InPattern + "]";
		generatePatternTestHelper(or2Context3InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr2WildcardContext2In() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForOr2WildcardContext2InPattern + "]";
		generatePatternTestHelper(or2WildcardContext2InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr2WildcardContext3In() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForOr2WildcardContext3InPattern + "]";
		generatePatternTestHelper(or2WildcardContext3InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr3Context2In() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForOr3Context2InPattern + "]";
		generatePatternTestHelper(or3Context2InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr3Context3In() {
		String testQueryPatternExpected = "{\"tables\":[" + emptyTable + "],\"steps\":["
				+ stepsForOr3Context3InPattern + "]";
		generatePatternTestHelper(or3Context3InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr3WildcardContext2In() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForOr3WildcardContext2InPattern + "]";
		generatePatternTestHelper(or3WildcardContext2InPattern, testQueryPatternExpected + this.getCompileInfo());
	}


	@Test
	public void testCompileOr3WildcardContext3In() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForOrPatterns + "],\"steps\":["
				+ stepsForOr3WildcardContext3InPattern + "]";
		generatePatternTestHelper(or3WildcardContext3InPattern, testQueryPatternExpected + this.getCompileInfo());
	}

	// Search tests
	@Test
	public void testSearchAmbiguousContextPattern() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program, this.program.getMinAddress(), ambiguousContextPattern);
		Assert.assertEquals(2, results.size());
		Assert.assertEquals(this.program.getMinAddress(), results.get(0).getStart());
		Assert.assertEquals(this.program.getMinAddress().add(4), results.get(1).getStart());
	}

	@Test
	public void testSearchContextBasedBranchPattern() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program, this.program.getMinAddress().add(8), contextBasedBranchPattern);
		Assert.assertEquals(1, results.size());
		Assert.assertEquals(this.program.getMinAddress().add(8), results.get(0).getStart());
	}

	@Test
	public void testSearchContextValidityPattern() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program, this.program.getMinAddress(), contextValidityPattern);
		Assert.assertEquals(1, results.size());
		Assert.assertEquals(this.program.getMinAddress().add(14), results.get(0).getStart());
	}

	@Test
	public void testSearchContextAnnotationPattern() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program, this.program.getMinAddress(), contextAnnotationPattern);
		Assert.assertEquals(2, results.size());
		Assert.assertEquals(this.program.getMinAddress().add(2), results.get(0).getStart());
		Assert.assertEquals(this.program.getMinAddress().add(22), results.get(1).getStart());
	}

	@Test
	public void testSearchNoflowContextPattern() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program, this.program.getMinAddress(), noflowContextPattern);
		Assert.assertEquals(1, results.size());
		Assert.assertEquals(this.program.getMinAddress().add(28), results.get(0).getStart());
	}
}
