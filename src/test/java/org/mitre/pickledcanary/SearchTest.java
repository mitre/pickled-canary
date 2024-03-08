
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary;

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mitre.pickledcanary.patterngenerator.output.steps.Byte;
import org.mitre.pickledcanary.patterngenerator.output.steps.Match;
import org.mitre.pickledcanary.patterngenerator.output.steps.Step;
import org.mitre.pickledcanary.search.Pattern;
import org.mitre.pickledcanary.search.SavedDataAddresses;
import org.mitre.pickledcanary.search.VmSearch;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.mem.Memory;

public class SearchTest extends PickledCanaryTest {

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("armle_test", "ARM:LE:32:v8");

		builder.setBytes("0x1008420", "40 00 13 e3 00 00");
		builder.applyDataType("0x1008420", new Pointer32DataType(), 1);
		builder.createLabel("0x1008420", "TEST_LABEL");
		builder.createLabel("0x1008424", "TEST_LABEL2");
		builder.createLabel("0x1000424", "TEST_LABEL3");

		setup(builder);
	}

	@Test
	public void testSearch() {
		Memory memory = program.getMemory();
		System.out.println(memory.toString());
		System.out.println(memory.getMinAddress().toString());

		List<Step> steps = new ArrayList<>();

		steps.add(new Byte(0x00));
		steps.add(new Match());
		Pattern pattern = new Pattern(steps, new ArrayList<>());

		Pattern start = Pattern.getDotStar();
		start.append(Pattern.getSaveStart());
		pattern.prepend(start);

		VmSearch vm = new VmSearch(pattern, program.getMemory());
		List<SavedDataAddresses> result = vm.runAll(monitor);
		if (result.size() == 0) {
			System.out.println("No match");
		} else {
			System.out.println("Match!");
			System.out.println(result.toString());
		}
		Assert.assertEquals(3, result.size());
		Assert.assertEquals(memory.getMinAddress().add(1), result.get(0).getStart());
		Assert.assertEquals(memory.getMinAddress().add(4), result.get(1).getStart());
		Assert.assertEquals(memory.getMinAddress().add(5), result.get(2).getStart());
		Assert.assertEquals(memory.getMinAddress().add(2), result.get(0).getEnd());
		Assert.assertEquals(memory.getMinAddress().add(5), result.get(1).getEnd());
		Assert.assertEquals(memory.getMinAddress().add(6), result.get(2).getEnd());
	}

	@Test
	public void testCompileAndRunPattern() {
		String patternIn = "tst r3,#0x40";
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
			program.getMemory().getMinAddress(), patternIn);
		Assert.assertEquals(this.program.getMinAddress(), results.get(0).getStart());
		Assert.assertEquals(this.program.getMinAddress().add(4), results.get(0).getEnd());
	}

	@Test
	public void testCompileAndRunPatternWildcard() {
		String patternIn = "tst `Q1`,#0x40";
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
			program.getMemory().getMinAddress(), patternIn);
		Assert.assertEquals(this.program.getMinAddress(), results.get(0).getStart());
		Assert.assertEquals(this.program.getMinAddress().add(4), results.get(0).getEnd());
		Assert.assertEquals("r3", results.get(0).variables.get("Q1").getValue());
	}

	@Test
	public void testCompileAndRunPatternLabel() {
		String patternIn = "`=0x13`\n`foo:`\n`=0xe3`";
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
			this.program.getMinAddress(), patternIn);
		Assert.assertEquals(this.program.getMinAddress().add(2), results.get(0).getStart());
		Assert.assertEquals(this.program.getMinAddress().add(4), results.get(0).getEnd());
		Assert.assertEquals(this.program.getMinAddress().add(3), results.get(0).labels.get("foo"));
	}

}
