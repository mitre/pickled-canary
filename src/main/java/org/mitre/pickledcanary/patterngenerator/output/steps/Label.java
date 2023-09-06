
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import org.json.JSONObject;

public class Label extends StepBranchless {

	private String value;

	public Label(String value) {
		super(StepType.LABEL, null);
		this.value = value;
	}

	public Label(String value, String note) {
		super(StepType.BYTE, note);
		this.value = value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();
		out.put("value", this.value);
		return out;
	}
}
