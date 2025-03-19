
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

/**
 * A step in the pattern that signifies a match has been found.
 */
public class Match extends StepBranchless {

	public Match() {
		super(StepType.MATCH, null);
	}

	public Match(String note) {
		super(StepType.MATCH, note);
	}

	@Override
	public String toString() {
		return "MATCH";
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
		Match other = (Match) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType);
	}

	@Override
	public int hashCode() {
		return stepType.hashCode();
	}
}
