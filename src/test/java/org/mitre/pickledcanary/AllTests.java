// Copyright (C) 2025 The MITRE Corporation All Rights Reserved
package org.mitre.pickledcanary;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;
import org.mitre.pickledcanary.gui.GuiTest;
import org.mitre.pickledcanary.headless.Aarch64LE64AppleSiliconPickledCanaryTest;
import org.mitre.pickledcanary.headless.ArmLePickledCanaryTest;
import org.mitre.pickledcanary.headless.ArmThumbLePickledCanaryTest;
import org.mitre.pickledcanary.headless.BitArrayTest;
import org.mitre.pickledcanary.headless.ContextTest;
import org.mitre.pickledcanary.headless.ExpressionSolverTest;
import org.mitre.pickledcanary.headless.MipsBePickledCanaryTest;
import org.mitre.pickledcanary.headless.MipsLePickledCanaryTest;
import org.mitre.pickledcanary.headless.MiscTest;
import org.mitre.pickledcanary.headless.SearchBenchmark;
import org.mitre.pickledcanary.headless.SearchTest;
import org.mitre.pickledcanary.headless.X86LePickledCanaryTest;
import org.mitre.pickledcanary.headless.X86_64LePickledCanaryTest;

@RunWith(Suite.class)

/**
 * Run all tests, both GUI and non-GUI.
 * 
 * For successful execution of GUI tests in eclipse, see note in the GuiTest
 * class.
 */
// All GUI tests must run before any non-GUI tests
@SuiteClasses(
	{
		// GUI Tests
		GuiTest.class,

		// Non-GUI Tests
		Aarch64LE64AppleSiliconPickledCanaryTest.class,
		ArmLePickledCanaryTest.class,
		ArmThumbLePickledCanaryTest.class,
		BitArrayTest.class,
		ContextTest.class,
		ExpressionSolverTest.class,
		MipsBePickledCanaryTest.class,
		MipsLePickledCanaryTest.class,
		MiscTest.class,
		SearchBenchmark.class,
		SearchTest.class,
		X86_64LePickledCanaryTest.class,
		X86LePickledCanaryTest.class
	}
)
public class AllTests {

}
