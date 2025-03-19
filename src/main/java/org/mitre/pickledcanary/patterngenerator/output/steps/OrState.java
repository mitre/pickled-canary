
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

/**
 * A construct that allows a pattern to have two branches.
 */
public class OrState {

	/**
	 * This is the index of the "split" for this OR
	 */
	private final int startStep;

	/**
	 * This is the index of the "jmp" after our first "or" option
	 */
	private int middleStep;

	public OrState(int startStep) {
		this.startStep = startStep;
		this.middleStep = -1;
	}

	public void setMiddleStep(int middleStep) {
		this.middleStep = middleStep;
	}

	public int getStartStep() {
		return this.startStep;
	}

	public int getMiddleStep() {
		return this.middleStep;
	}
}
