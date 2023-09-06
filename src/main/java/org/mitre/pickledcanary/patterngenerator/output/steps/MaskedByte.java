
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import org.json.JSONObject;

public class MaskedByte extends StepBranchless {

	private int mask;
	private int value;

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

	public void setMask(int mask) {
		this.mask = mask;
	}

	public void setValue(int value) {
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
}
