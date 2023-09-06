
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

public class SaveStart extends StepBranchless {

	public SaveStart() {
		super(StepType.SAVESTART, null);
	}

	public SaveStart(String note) {
		super(StepType.SAVESTART, note);
	}
}
