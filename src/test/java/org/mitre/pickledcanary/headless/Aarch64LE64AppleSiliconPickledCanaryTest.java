
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.headless;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;

public class Aarch64LE64AppleSiliconPickledCanaryTest extends PickledCanaryTest {

	@Override
	protected String getCompileInfoRaw() {
		return ",\"compile_info\":[{\"compiled_using_binary\":[{\"path\":[\"unknown\"],\"compiled_at_address\":[\"01006420\"],\"md5\":[\"unknown\"]}],\"language_id\":[\"AARCH64:LE:64:AppleSilicon\"]}],\"pattern_metadata\":{}}";
	}

	private static final String tablesForMultiWildcardMultiTable = "{\"w30\":[{\"value\":[30],\"mask\":[31]}]},{\"w30\":[{\"value\":[192,3],\"mask\":[224,3]}]}";
	private static final String stepsForMultiWildcardMultiTable = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":1,\"mask\":[224,3,0,0]},{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[31,0,0,0]}],\"value\":[0,64,0,17]}],\"mask\":[0,252,255,255]}],\"type\":\"LOOKUP\"}";
	private static final String multiWildcardMultiTable = "add `Q2/w30`,`Q1/w30`,#0x10";

	static final int dataBase = 0x1008420;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("aarch64_test", "AARCH64:LE:64:AppleSilicon");
		builder.setBytes(String.format("0x%08X", dataBase),
			"ff ");
		program = builder.getProgram();
	}

	@Test
	public void testMultiWildcardMultiTable() {
		List<String> testQueryPatternExpected = new ArrayList<>();
		testQueryPatternExpected.add(
				"{\"tables\":[" + tablesForMultiWildcardMultiTable + "],\"steps\":[" + stepsForMultiWildcardMultiTable + "]" + this.getCompileInfo());

		generatePatternTestHelper(multiWildcardMultiTable, testQueryPatternExpected);
	}
}
