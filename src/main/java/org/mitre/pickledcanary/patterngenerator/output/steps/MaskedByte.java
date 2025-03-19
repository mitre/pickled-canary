
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

import org.json.JSONObject;

/**
 * A step in the pattern that matches a byte with a mask applied.
 */
public class MaskedByte extends StepBranchless {

	private final int mask;
	private final int value;

	public MaskedByte(int mask, int value) {
		super(StepType.MASKEDBYTE, null);
		this.mask = mask;
		this.value = value;
	}

	public MaskedByte(int mask, int value, String note) {
		super(StepType.MASKEDBYTE, note);
		this.mask = mask;
		this.value = value;
	}

	public int getValue() {
		return this.value;
	}

	public int getMask() {
		return this.mask;
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();
		out.put("mask", this.mask);
		out.put("value", this.value);
		return out;
	}

	@Override
	public String toString() {
		return "MASKED BYTE Mask: " + mask + "; Value: " + value;
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
		MaskedByte other = (MaskedByte) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType) && this.mask == other.mask &&
			this.value == other.value;
	}

	@Override
	public int hashCode() {
		return Objects.hash(stepType, mask, value);
	}
}
