
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

import org.json.JSONObject;

/**
 * A step that creates two branches in a pattern.
 */
public class Split extends Step {

	private int dest1;
	private int dest2;

	public Split(int dest1) {
		super(StepType.SPLIT, null);
		this.dest1 = dest1;
	}

	public Split(int dest1, String note) {
		super(StepType.SPLIT, note);
		this.dest1 = dest1;
	}

	public Split(int dest1, int dest2) {
		super(StepType.SPLIT, null);
		this.dest1 = dest1;
		this.dest2 = dest2;
	}

	public Split(int dest1, int dest2, String note) {
		super(StepType.SPLIT, note);
		this.dest1 = dest1;
		this.dest2 = dest2;
	}

	public int getDest1() {
		return this.dest1;
	}

	public int getDest2() {
		return this.dest2;
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();
		out.put("dest1", dest1);
		out.put("dest2", dest2);
		return out;
	}

	@Override
	public void increment(int amount, int threshold) {
		if (this.dest1 >= threshold) {
			this.dest1 += amount;
		}
		if (this.dest2 >= threshold) {
			this.dest2 += amount;
		}
	}

	@Override
	public String toString() {
		return "SPLIT Dest1: " + this.dest1 + "; Dest2: " + this.dest2;
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
		Split other = (Split) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType) && this.dest1 == other.dest1 &&
			this.dest2 == other.dest2;
	}

	@Override
	public int hashCode() {
		return Objects.hash(stepType, dest1, dest2);
	}
}
