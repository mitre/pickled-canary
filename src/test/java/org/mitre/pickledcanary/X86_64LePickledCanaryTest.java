
// Copyright (C) 2024 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;

public class X86_64LePickledCanaryTest extends PickledCanaryTest {

	@Override
	protected String getCompileInfoRaw() {
		return ",\"compile_info\":[{\"compiled_using_binary\":[{\"path\":[\"unknown\"],\"compiled_at_address\":[\"01006420\"],\"md5\":[\"unknown\"]}],\"language_id\":[\"x86:LE:64:default\"]}],\"pattern_metadata\":{}}";
	}

	private static final String simpleWildcardInstruction2 = "LEA EAX, [ `Q1` + -0x6c ]";
	private static final String stepsForSimpleWildcardInstruction2 = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":3,\"mask\":[0,7,0]}],\"value\":[141,64,148]}],\"mask\":[255,248,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":2,\"mask\":[0,0,0,7,0,0,0,0]}],\"value\":[103,65,141,128,148,255,255,255]}],\"mask\":[255,253,255,248,255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":6,\"mask\":[0,0,0,0,7,0]}],\"value\":[103,65,141,68,32,148]}],\"mask\":[255,253,255,255,56,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":7,\"mask\":[0,0,7,0]}],\"value\":[141,68,32,148]}],\"mask\":[255,255,56,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,0,7,0]}],\"value\":[103,141,64,148]}],\"mask\":[255,255,248,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":1,\"mask\":[0,0,7,0]}],\"value\":[65,141,64,148]}],\"mask\":[253,255,248,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":5,\"mask\":[0,0,0,7,0,0,0,0]}],\"value\":[65,141,132,32,148,255,255,255]},{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":4,\"mask\":[0,0,0,7,0,0,0,0]}],\"value\":[103,141,132,32,148,255,255,255]}],\"mask\":[255,255,255,56,255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,0,7,0,0,0,0]}],\"value\":[103,141,128,148,255,255,255]}],\"mask\":[255,255,248,255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":5,\"mask\":[0,0,0,7,0]}],\"value\":[65,141,68,32,148]},{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":4,\"mask\":[0,0,0,7,0]}],\"value\":[103,141,68,32,148]}],\"mask\":[255,255,255,56,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":7,\"mask\":[0,0,7,0,0,0,0]}],\"value\":[141,132,32,148,255,255,255]}],\"mask\":[255,255,56,255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":2,\"mask\":[0,0,0,7,0]}],\"value\":[103,65,141,64,148]}],\"mask\":[255,253,255,248,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":3,\"mask\":[0,7,0,0,0,0]}],\"value\":[141,128,148,255,255,255]}],\"mask\":[255,248,255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":1,\"mask\":[0,0,7,0,0,0,0]}],\"value\":[65,141,128,148,255,255,255]}],\"mask\":[253,255,248,255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":6,\"mask\":[0,0,0,0,7,0,0,0,0]}],\"value\":[103,65,141,132,32,148,255,255,255]}],\"mask\":[255,253,255,255,56,255,255,255,255]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForSimpleWildcardInstruction2 = "{\"EBP\":[{\"value\":[5],\"mask\":[7]}],\"EDX\":[{\"value\":[2],\"mask\":[7]}],\"EBX\":[{\"value\":[3],\"mask\":[7]}],\"ESI\":[{\"value\":[6],\"mask\":[7]}],\"ECX\":[{\"value\":[1],\"mask\":[7]}],\"EDI\":[{\"value\":[7],\"mask\":[7]}],\"EAX\":[{\"value\":[0],\"mask\":[7]}]},{\"R10\":[{\"value\":[2],\"mask\":[7]}],\"R11\":[{\"value\":[3],\"mask\":[7]}],\"R14\":[{\"value\":[6],\"mask\":[7]}],\"R13\":[{\"value\":[5],\"mask\":[7]}],\"R8\":[{\"value\":[0],\"mask\":[7]}],\"R9\":[{\"value\":[1],\"mask\":[7]}],\"R15\":[{\"value\":[7],\"mask\":[7]}]},{\"R11D\":[{\"value\":[3],\"mask\":[7]}],\"R10D\":[{\"value\":[2],\"mask\":[7]}],\"R13D\":[{\"value\":[5],\"mask\":[7]}],\"R15D\":[{\"value\":[7],\"mask\":[7]}],\"R14D\":[{\"value\":[6],\"mask\":[7]}],\"R9D\":[{\"value\":[1],\"mask\":[7]}],\"R8D\":[{\"value\":[0],\"mask\":[7]}]},{\"RBP\":[{\"value\":[5],\"mask\":[7]}],\"RCX\":[{\"value\":[1],\"mask\":[7]}],\"RDI\":[{\"value\":[7],\"mask\":[7]}],\"RDX\":[{\"value\":[2],\"mask\":[7]}],\"RAX\":[{\"value\":[0],\"mask\":[7]}],\"RBX\":[{\"value\":[3],\"mask\":[7]}],\"RSI\":[{\"value\":[6],\"mask\":[7]}]},{\"EBP\":[{\"value\":[5],\"mask\":[7]}],\"ESP\":[{\"value\":[4],\"mask\":[7]}],\"EDX\":[{\"value\":[2],\"mask\":[7]}],\"EBX\":[{\"value\":[3],\"mask\":[7]}],\"ESI\":[{\"value\":[6],\"mask\":[7]}],\"ECX\":[{\"value\":[1],\"mask\":[7]}],\"EDI\":[{\"value\":[7],\"mask\":[7]}],\"EAX\":[{\"value\":[0],\"mask\":[7]}]},{\"R10\":[{\"value\":[2],\"mask\":[7]}],\"R12\":[{\"value\":[4],\"mask\":[7]}],\"R11\":[{\"value\":[3],\"mask\":[7]}],\"R14\":[{\"value\":[6],\"mask\":[7]}],\"R13\":[{\"value\":[5],\"mask\":[7]}],\"R8\":[{\"value\":[0],\"mask\":[7]}],\"R9\":[{\"value\":[1],\"mask\":[7]}],\"R15\":[{\"value\":[7],\"mask\":[7]}]},{\"R11D\":[{\"value\":[3],\"mask\":[7]}],\"R10D\":[{\"value\":[2],\"mask\":[7]}],\"R13D\":[{\"value\":[5],\"mask\":[7]}],\"R12D\":[{\"value\":[4],\"mask\":[7]}],\"R15D\":[{\"value\":[7],\"mask\":[7]}],\"R14D\":[{\"value\":[6],\"mask\":[7]}],\"R9D\":[{\"value\":[1],\"mask\":[7]}],\"R8D\":[{\"value\":[0],\"mask\":[7]}]},{\"RBP\":[{\"value\":[5],\"mask\":[7]}],\"RCX\":[{\"value\":[1],\"mask\":[7]}],\"RDI\":[{\"value\":[7],\"mask\":[7]}],\"RDX\":[{\"value\":[2],\"mask\":[7]}],\"RAX\":[{\"value\":[0],\"mask\":[7]}],\"RBX\":[{\"value\":[3],\"mask\":[7]}],\"RSI\":[{\"value\":[6],\"mask\":[7]}],\"RSP\":[{\"value\":[4],\"mask\":[7]}]}";

	// This is mostly to test that we can parse this long instruction with lots of
	// suboperands
	private static final String lotsOfSuboperands = "MOV RAX , qword ptr [ R10 + R12 * 2 + 01 ]";
	private static final String stepsForLotsOfSuboperands = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[75,139,68,98,1]}],\"mask\":[255,255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[75,139,132,98,1,0,0,0]}],\"mask\":[255,255,255,255,255,255,255,255]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForLotsOfSuboperands = "";

	private static final String callDx = "CALL `*/DX`";
	private static final String stepsForCallDx = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[102,255,208]}],\"mask\":[255,255,248]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[102,103,255,208]},{\"operands\":[],\"value\":[103,102,255,208]}],\"mask\":[255,255,255,248]}],\"type\":\"LOOKUP\"}";
	private static final String stepsForCallDx_10_3_1 = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[102,255,208]}],\"mask\":[255,255,248]}],\"type\":\"LOOKUP\"}";
    private static final String tablesForCallDx = "";

	final int dataBase = 0x1008420;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("x86_test", "x86:LE:64:default");
		builder.setBytes(String.format("0x%08X", dataBase), "ff ");

		setup(builder);
	}

	@Test
	public void testPatternWithWildcard2() {
		List<String> testQueryPatternExpected = new ArrayList<>();
		testQueryPatternExpected.add("{\"tables\":[" + tablesForSimpleWildcardInstruction2 + "],\"steps\":["
				+ stepsForSimpleWildcardInstruction2 + "]" + getCompileInfo());
		
		generatePatternTestHelper(simpleWildcardInstruction2, testQueryPatternExpected);
	}

	/* See notes above variables this function uses */
	@Test
	public void testLotsOfSuboperands() {
		List<String> testQueryPatternExpected = new ArrayList<>();
		testQueryPatternExpected.add("{\"tables\":[" + tablesForLotsOfSuboperands + "],\"steps\":["
				+ stepsForLotsOfSuboperands + "]" + getCompileInfo());
		generatePatternTestHelper(lotsOfSuboperands, testQueryPatternExpected);
	}

	@Test
	public void testCallDx() {
		List<String> testQueryPatternExpected = new ArrayList<>();
        testQueryPatternExpected.add("{\"tables\":[" + tablesForCallDx + "],\"steps\":["
                + stepsForCallDx + "]" + getCompileInfo());
        testQueryPatternExpected.add("{\"tables\":[" + tablesForCallDx + "],\"steps\":["
                + stepsForCallDx_10_3_1 + "]" + getCompileInfo());
		generatePatternTestHelper(callDx, testQueryPatternExpected);
	}
}
