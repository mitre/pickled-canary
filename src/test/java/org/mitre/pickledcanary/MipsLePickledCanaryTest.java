
// Copyright (C) 2024 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;

public class MipsLePickledCanaryTest extends PickledCanaryTest {

	@Override
	protected String getCompileInfoRaw() {
		return ",\"compile_info\":[{\"compiled_using_binary\":[{\"path\":[\"unknown\"],\"compiled_at_address\":[\"01006420\"],\"md5\":[\"unknown\"]}],\"language_id\":[\"MIPS:LE:32:default\"]}],\"pattern_metadata\":{}}";
	}

	private static final String simpleSuboperandInstruction = "lw v1,0xc8(`Q1`)";
	private static final String stepsForSimpleSuboperandInstruction = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,0,224,3]}],\"value\":[200,0,3,140]}],\"mask\":[255,255,31,252]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForSimpleSuboperandInstruction = "{\"t4\":[{\"value\":[128,1],\"mask\":[224,3]}],\"t5\":[{\"value\":[160,1],\"mask\":[224,3]}],\"t6\":[{\"value\":[192,1],\"mask\":[224,3]}],\"t7\":[{\"value\":[224,1],\"mask\":[224,3]}],\"t8\":[{\"value\":[0,3],\"mask\":[224,3]}],\"t9\":[{\"value\":[32,3],\"mask\":[224,3]}],\"zero\":[{\"value\":[0,0],\"mask\":[224,3]}],\"s0\":[{\"value\":[0,2],\"mask\":[224,3]}],\"sp\":[{\"value\":[160,3],\"mask\":[224,3]}],\"s1\":[{\"value\":[32,2],\"mask\":[224,3]}],\"s2\":[{\"value\":[64,2],\"mask\":[224,3]}],\"s3\":[{\"value\":[96,2],\"mask\":[224,3]}],\"s4\":[{\"value\":[128,2],\"mask\":[224,3]}],\"s5\":[{\"value\":[160,2],\"mask\":[224,3]}],\"s6\":[{\"value\":[192,2],\"mask\":[224,3]}],\"s7\":[{\"value\":[224,2],\"mask\":[224,3]}],\"k0\":[{\"value\":[64,3],\"mask\":[224,3]}],\"s8\":[{\"value\":[192,3],\"mask\":[224,3]}],\"k1\":[{\"value\":[96,3],\"mask\":[224,3]}],\"gp\":[{\"value\":[128,3],\"mask\":[224,3]}],\"a0\":[{\"value\":[128,0],\"mask\":[224,3]}],\"ra\":[{\"value\":[224,3],\"mask\":[224,3]}],\"a1\":[{\"value\":[160,0],\"mask\":[224,3]}],\"a2\":[{\"value\":[192,0],\"mask\":[224,3]}],\"a3\":[{\"value\":[224,0],\"mask\":[224,3]}],\"at\":[{\"value\":[32,0],\"mask\":[224,3]}],\"v0\":[{\"value\":[64,0],\"mask\":[224,3]}],\"v1\":[{\"value\":[96,0],\"mask\":[224,3]}],\"t0\":[{\"value\":[0,1],\"mask\":[224,3]}],\"t1\":[{\"value\":[32,1],\"mask\":[224,3]}],\"t2\":[{\"value\":[64,1],\"mask\":[224,3]}],\"t3\":[{\"value\":[96,1],\"mask\":[224,3]}]}";

	private static final String heartbleed = 
			"li a2,0x18\n"
			+ "`ANY_BYTES{0,50}`\n"
			+ "addiu `Q1`,`*`,0x13\n"
			+ "move a0,`Q1`\n"
			+ "`ANY_BYTES{0,4}`\n"
			+ "jalr `*`";
	private static final String stepsForHeartbleed = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[24,0,6,36]}],\"mask\":[255,255,255,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 0 End: 50 Interval: 1 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{0,50}`\",\"min\":0,\"max\":50,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":2,\"mask\":[0,0,31,0]}],\"value\":[19,0,0,36]}],\"mask\":[255,255,0,252]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,0,31,0]}],\"value\":[33,32,0,0]}],\"mask\":[255,255,224,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":1,\"mask\":[0,0,224,3]}],\"value\":[33,32,0,0]}],\"mask\":[255,255,31,252]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 0 End: 4 Interval: 1 From: Token from line #5: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{0,4}`\",\"min\":0,\"max\":4,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[9,248,0,0]}],\"mask\":[63,248,31,252]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForHeartbleed = "{\"t4\":[{\"value\":[12],\"mask\":[31]}],\"t5\":[{\"value\":[13],\"mask\":[31]}],\"t6\":[{\"value\":[14],\"mask\":[31]}],\"t7\":[{\"value\":[15],\"mask\":[31]}],\"t8\":[{\"value\":[24],\"mask\":[31]}],\"t9\":[{\"value\":[25],\"mask\":[31]}],\"s0\":[{\"value\":[16],\"mask\":[31]}],\"sp\":[{\"value\":[29],\"mask\":[31]}],\"s1\":[{\"value\":[17],\"mask\":[31]}],\"s2\":[{\"value\":[18],\"mask\":[31]}],\"s3\":[{\"value\":[19],\"mask\":[31]}],\"s4\":[{\"value\":[20],\"mask\":[31]}],\"s5\":[{\"value\":[21],\"mask\":[31]}],\"s6\":[{\"value\":[22],\"mask\":[31]}],\"s7\":[{\"value\":[23],\"mask\":[31]}],\"k0\":[{\"value\":[26],\"mask\":[31]}],\"s8\":[{\"value\":[30],\"mask\":[31]}],\"k1\":[{\"value\":[27],\"mask\":[31]}],\"gp\":[{\"value\":[28],\"mask\":[31]}],\"a0\":[{\"value\":[4],\"mask\":[31]}],\"ra\":[{\"value\":[31],\"mask\":[31]}],\"a1\":[{\"value\":[5],\"mask\":[31]}],\"a2\":[{\"value\":[6],\"mask\":[31]}],\"a3\":[{\"value\":[7],\"mask\":[31]}],\"at\":[{\"value\":[1],\"mask\":[31]}],\"v0\":[{\"value\":[2],\"mask\":[31]}],\"v1\":[{\"value\":[3],\"mask\":[31]}],\"t0\":[{\"value\":[8],\"mask\":[31]}],\"t1\":[{\"value\":[9],\"mask\":[31]}],\"t2\":[{\"value\":[10],\"mask\":[31]}],\"t3\":[{\"value\":[11],\"mask\":[31]}]},{\"t4\":[{\"value\":[128,1],\"mask\":[224,3]}],\"t5\":[{\"value\":[160,1],\"mask\":[224,3]}],\"t6\":[{\"value\":[192,1],\"mask\":[224,3]}],\"t7\":[{\"value\":[224,1],\"mask\":[224,3]}],\"t8\":[{\"value\":[0,3],\"mask\":[224,3]}],\"t9\":[{\"value\":[32,3],\"mask\":[224,3]}],\"s0\":[{\"value\":[0,2],\"mask\":[224,3]}],\"sp\":[{\"value\":[160,3],\"mask\":[224,3]}],\"s1\":[{\"value\":[32,2],\"mask\":[224,3]}],\"s2\":[{\"value\":[64,2],\"mask\":[224,3]}],\"s3\":[{\"value\":[96,2],\"mask\":[224,3]}],\"s4\":[{\"value\":[128,2],\"mask\":[224,3]}],\"s5\":[{\"value\":[160,2],\"mask\":[224,3]}],\"s6\":[{\"value\":[192,2],\"mask\":[224,3]}],\"s7\":[{\"value\":[224,2],\"mask\":[224,3]}],\"k0\":[{\"value\":[64,3],\"mask\":[224,3]}],\"s8\":[{\"value\":[192,3],\"mask\":[224,3]}],\"k1\":[{\"value\":[96,3],\"mask\":[224,3]}],\"gp\":[{\"value\":[128,3],\"mask\":[224,3]}],\"a0\":[{\"value\":[128,0],\"mask\":[224,3]}],\"ra\":[{\"value\":[224,3],\"mask\":[224,3]}],\"a1\":[{\"value\":[160,0],\"mask\":[224,3]}],\"a2\":[{\"value\":[192,0],\"mask\":[224,3]}],\"a3\":[{\"value\":[224,0],\"mask\":[224,3]}],\"at\":[{\"value\":[32,0],\"mask\":[224,3]}],\"v0\":[{\"value\":[64,0],\"mask\":[224,3]}],\"v1\":[{\"value\":[96,0],\"mask\":[224,3]}],\"t0\":[{\"value\":[0,1],\"mask\":[224,3]}],\"t1\":[{\"value\":[32,1],\"mask\":[224,3]}],\"t2\":[{\"value\":[64,1],\"mask\":[224,3]}],\"t3\":[{\"value\":[96,1],\"mask\":[224,3]}]},{\"t4\":[{\"value\":[12],\"mask\":[31]}],\"t5\":[{\"value\":[13],\"mask\":[31]}],\"t6\":[{\"value\":[14],\"mask\":[31]}],\"t7\":[{\"value\":[15],\"mask\":[31]}],\"t8\":[{\"value\":[24],\"mask\":[31]}],\"t9\":[{\"value\":[25],\"mask\":[31]}],\"zero\":[{\"value\":[0],\"mask\":[31]}],\"s0\":[{\"value\":[16],\"mask\":[31]}],\"sp\":[{\"value\":[29],\"mask\":[31]}],\"s1\":[{\"value\":[17],\"mask\":[31]}],\"s2\":[{\"value\":[18],\"mask\":[31]}],\"s3\":[{\"value\":[19],\"mask\":[31]}],\"s4\":[{\"value\":[20],\"mask\":[31]}],\"s5\":[{\"value\":[21],\"mask\":[31]}],\"s6\":[{\"value\":[22],\"mask\":[31]}],\"s7\":[{\"value\":[23],\"mask\":[31]}],\"k0\":[{\"value\":[26],\"mask\":[31]}],\"s8\":[{\"value\":[30],\"mask\":[31]}],\"k1\":[{\"value\":[27],\"mask\":[31]}],\"gp\":[{\"value\":[28],\"mask\":[31]}],\"a0\":[{\"value\":[4],\"mask\":[31]}],\"ra\":[{\"value\":[31],\"mask\":[31]}],\"a1\":[{\"value\":[5],\"mask\":[31]}],\"a2\":[{\"value\":[6],\"mask\":[31]}],\"a3\":[{\"value\":[7],\"mask\":[31]}],\"at\":[{\"value\":[1],\"mask\":[31]}],\"v0\":[{\"value\":[2],\"mask\":[31]}],\"v1\":[{\"value\":[3],\"mask\":[31]}],\"t0\":[{\"value\":[8],\"mask\":[31]}],\"t1\":[{\"value\":[9],\"mask\":[31]}],\"t2\":[{\"value\":[10],\"mask\":[31]}],\"t3\":[{\"value\":[11],\"mask\":[31]}]}";

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("mips_test", "MIPS:LE:32:default");
		builder.setBytes(String.format("0x%08X", 0x10000), "ff ");
		setup(builder);
	}

	@Test
	public void testPatternWithSuboperand() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForSimpleSuboperandInstruction + "],\"steps\":["
				+ stepsForSimpleSuboperandInstruction + "]";
		generatePatternTestHelper(simpleSuboperandInstruction, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testHeartbleed() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForHeartbleed + "],\"steps\":[" + stepsForHeartbleed
				+ "]";
		generatePatternTestHelper(heartbleed, testQueryPatternExpected + getCompileInfo());
	}
}
