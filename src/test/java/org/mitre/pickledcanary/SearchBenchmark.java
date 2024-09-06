package org.mitre.pickledcanary;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.Assert;
import org.mitre.pickledcanary.search.Pattern;
import org.mitre.pickledcanary.search.SavedDataAddresses;

import ghidra.program.database.ProgramBuilder;

public class SearchBenchmark extends PickledCanaryTest {

	@Override
	protected String getCompileInfoRaw() {
		return ",\"compile_info\":[{\"compiled_using_binary\":[{\"path\":[\"unknown\"],\"compiled_at_address\":[\"00001000\"],\"md5\":[\"unknown\"]}],\"language_id\":[\"ARM:LE:32:v8\"]}],\"pattern_metadata\":{}}";
	}

	Pattern v1;
	Pattern v2;
	static final int dataBase = 0x1000;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("arm_le_benchmark", "AARCH64:LE:64:AppleSilicon");
		
		int size = 0x1000*0x1000*0x4;

		builder.setBytes(String.format("0x%08X", dataBase), new byte[size]);
		builder.setBytes(String.format("0x%08X", dataBase + (size)),
			"aa 01 03 f3 f3 03 01 aa 00 00 00");

		program = builder.getProgram();

		v1 = PickledCanary.compileWrapped(monitor, "mov `q1`,`q2`", program,
			program.getMinAddress());

		System.out.println(v1.toString());
	}

	@Test
	public void testV1() {
		List<SavedDataAddresses> results = PickledCanary.runAll(monitor, program, v1);
		Assert.assertEquals(1, results.size());
	}
}
