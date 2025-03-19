
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

import org.json.JSONObject;

/**
 * Represents a step in the pattern that jumps to a particular step.
 */
public class Jmp extends Step {

	private int dest;

	public Jmp(int dest) {
		super(StepType.JMP, null);
		this.dest = dest;
	}

	public Jmp(int dest, String note) {
		super(StepType.JMP, note);
		this.dest = dest;
	}

	public void setDest(int dest) {
		this.dest = dest;
	}

	public int getDest() {
		return this.dest;
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();
		out.put("dest", this.dest);
		return out;
	}

	@Override
	public void increment(int amount, int threshold) {
		if (this.dest >= threshold) {
			this.dest += amount;
		}
	}

	@Override
	public String toString() {
		return "JMP Dest: " + this.dest;
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
		Jmp other = (Jmp) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType) && this.dest == other.dest;
	}

	@Override
	public int hashCode() {
		return Objects.hash(stepType, dest);
	}
}
