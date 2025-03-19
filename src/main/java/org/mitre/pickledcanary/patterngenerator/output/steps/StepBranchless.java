
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

/**
 * Same as a step, but classes that inherit this guarantee they only ever fall
 * through to the next instruction. they have no branches or jumps
 */
public abstract class StepBranchless extends Step {

	protected StepBranchless(StepType stepType, String note) {
		super(stepType, note);
	}

	@Override
	public void increment(int amount, int threshold) {
		// Do nothing
	}

}
