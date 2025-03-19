
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;
import java.util.List;

/**
 * A construct that allows patterns to contain multiple branches.
 */
public class OrMultiState {

	/**
	 * This is the index of the "split" for this OR
	 */
	private final int startStep;

	/**
	 * This is the index of the "jmp" after our first "or" option
	 */
	private final List<Integer> middleSteps;

	public OrMultiState(int startStep) {
		this.startStep = startStep;
		this.middleSteps = new ArrayList<>();
	}

	public void addMiddleStep(int middleStep) {
		this.middleSteps.add(middleStep);
	}

	public int getStartStep() {
		return this.startStep;
	}

	public List<Integer> getMiddleSteps() {
		return this.middleSteps;
	}
}
