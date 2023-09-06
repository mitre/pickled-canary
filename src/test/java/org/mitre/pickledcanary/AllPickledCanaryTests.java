
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)

@Suite.SuiteClasses({
   ArmLePickledCanaryTest.class,
   ArmThumbLePickledCanaryTest.class,
   BitArrayTest.class,
   MipsBePickledCanaryTest.class,
   MipsLePickledCanaryTest.class,
   PickledCanaryInstructionNodeTest.class,
   SearchTest.class,
   X86_64LePickledCanaryTest.class,
   X86LePickledCanaryTest.class
})

/**
 * Run this file as a junit test to run all Pickled Canary tests.
 */
public class AllPickledCanaryTests {

}
