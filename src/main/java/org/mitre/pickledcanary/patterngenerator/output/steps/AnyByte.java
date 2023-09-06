
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

public class AnyByte extends StepBranchless {

	public AnyByte() {
		super(StepType.ANYBYTE, null);
	}

	public AnyByte(String note) {
		super(StepType.ANYBYTE, note);
	}

	public String toString() {
		return "AnyByte";
	}
}
