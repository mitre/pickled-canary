
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

import org.json.JSONObject;

/**
 * A step in the pattern that matches a byte of a particular value.
 */
public class Byte extends StepBranchless {

	private final int value;

	public Byte(int value) {
		super(StepType.BYTE, null);
		checkValue(value);
		this.value = value;
	}

	public Byte(int value, String note) {
		super(StepType.BYTE, note);
		checkValue(value);
		this.value = value;
	}

	private void checkValue(int valueIn) {
		if (valueIn > 255) {
			throw new IllegalArgumentException("Byte value must be <255!");
		}
	}

	public int getValue() {
		return this.value;
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();
		out.put("value", this.value);
		return out;
	}

	@Override
	public String toString() {
		return "BYTE Value: " + this.value;
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
		Byte other = (Byte) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType) && this.value == other.value;
	}

	@Override
	public int hashCode() {
		return Objects.hash(stepType, value);
	}
}
