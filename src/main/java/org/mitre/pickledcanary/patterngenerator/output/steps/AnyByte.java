
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

/**
 * Represents a step in the pattern that matches any one byte regardless of the byte's value.
 */
public class AnyByte extends StepBranchless {

	public AnyByte() {
		super(StepType.ANYBYTE, null);
	}

	public AnyByte(String note) {
		super(StepType.ANYBYTE, note);
	}

	@Override
	public String toString() {
		return "AnyByte";
	}

	@Override
	public boolean equals(Object o) {
		// self check
		if (this == o) {
			return true;
		}
		// null check
		// type check and cast
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		AnyByte other = (AnyByte) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType);
	}

	@Override
	public int hashCode() {
		return stepType.hashCode();
	}
}
