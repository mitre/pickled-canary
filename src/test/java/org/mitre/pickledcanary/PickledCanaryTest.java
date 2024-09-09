
// Copyright (C) 2024 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import org.junit.Assert;

import java.util.ArrayList;
import java.util.List;

/**
 * Super class for Pickled Canary tests. Each language ID gets its own subclass.
 */
public abstract class PickledCanaryTest extends AbstractGhidraHeadlessIntegrationTest {

	static final TaskMonitor monitor = TaskMonitor.DUMMY;

	Program program;

	/**
	 * Call in the setUp() method in the subclasses.
	 * 
	 * @param builder program builder that sets the language and other program specs
	 */
	void setup(ProgramBuilder builder) {
		program = builder.getProgram();
	}

	/**
	 * Run test for pattern that is expected to compile.
	 * 
	 * @param patternIn       assembly pattern
	 * @param compiledPattern expected compiled pattern
	 */
	void generatePatternTestHelper(String patternIn, String compiledPattern) {
		List<String> expected = new ArrayList<>();
		expected.add(compiledPattern);
		generatePatternTestHelper(patternIn, expected, false);
	}

	/**
	 * Run test for pattern that is expected to compile.
	 * 
	 * @param patternIn       assembly pattern
	 * @param compiledPattern expected compiled pattern
	 * @param address         the address where the pattern should be compiled
	 */
	void generatePatternTestHelper(String patternIn, String compiledPattern, Address address) {
		List<String> expected = new ArrayList<>();
		expected.add(compiledPattern);
		generatePatternTestHelper(patternIn, expected, false, address);
	}

	/**
	 * Run test for pattern that is expected to compile.
	 * 
	 * @param patternIn       assembly pattern
	 * @param compiledPattern expected compiled pattern
	 */
	void generatePatternTestHelper(String patternIn, String compiledPattern, boolean removeDebugInfo) {
		List<String> expected = new ArrayList<>();
		expected.add(compiledPattern);
		generatePatternTestHelper(patternIn, expected, removeDebugInfo);
	}

	/**
	 * Run test for pattern that is expected to compile.
	 * 
	 * @param patternIn       assembly pattern
	 * @param compiledPattern list of correct compiled patterns
	 */
	void generatePatternTestHelper(String patternIn, List<String> compiledPattern) {
		generatePatternTestHelper(patternIn, compiledPattern, false);
	}

	/**
	 * Run test for pattern that is expected to compile.
	 * 
	 * @param patternIn       assembly pattern
	 * @param compiledPattern list of correct compiled patterns
	 */
	void generatePatternTestHelper(String patternIn, List<String> compiledPattern, Address address) {
		generatePatternTestHelper(patternIn, compiledPattern, false, address);
	}

	/**
	 * Run test for pattern that is expected to compile.
	 * 
	 * @param patternIn       assembly pattern
	 * @param compiledPattern list of correct compiled patterns
	 */
	void generatePatternTestHelper(String patternIn, List<String> compiledPattern, boolean removeDebugInfo) {
		generatePatternTestHelper(patternIn, compiledPattern, removeDebugInfo, this.program.getMinAddress());
	}

	/**
	 * Run test for pattern that is expected to compile.
	 * 
	 * @param patternIn       assembly pattern
	 * @param compiledPattern list of correct compiled patterns
	 * @param address         the address where the pattern should be compiled
	 */
	void generatePatternTestHelper(String patternIn, List<String> compiledPattern, boolean removeDebugInfo,
			Address address) {
		String actuallyCompiledPattern = "";
		actuallyCompiledPattern = PickledCanary.compile(monitor, patternIn, this.program, address,
			removeDebugInfo);

		boolean result = false;
		for (String target : compiledPattern) {
			result |= actuallyCompiledPattern.equals(target);
		}

		Assert.assertTrue("Pattern result:\n" + actuallyCompiledPattern + "\n\nShould match one of:\n" + compiledPattern
				+ "\n\nBut it does not!", result);
	}

	protected String getCompileInfoRaw() {
		return "";
	}

	protected String getCompileInfo() {
		return getCompileInfo(this.program.getMinAddress());
	}

	protected String getCompileInfo(Address address) {
		return this.getCompileInfoRaw().replaceAll("compiled_at_address\":\\[\"[0-9A-Fa-f]+\"\\]",
				"compiled_at_address\":[\"" + address.toString() + "\"]");
	}
}
