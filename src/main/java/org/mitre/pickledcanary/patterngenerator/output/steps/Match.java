
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

public class Match extends StepBranchless {

	public Match() {
		super(StepType.MATCH, null);
	}

	public Match(String note) {
		super(StepType.MATCH, note);
	}
}
