
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import org.json.JSONObject;

public class NegativeLookahead extends StepBranchless {

	private JSONObject pattern;

	public NegativeLookahead(JSONObject pattern) {
		super(StepType.NEGATIVELOOKAHEAD, null);
		this.pattern = pattern;
	}

	public NegativeLookahead(JSONObject pattern, String note) {
		super(StepType.NEGATIVELOOKAHEAD, note);
		this.pattern = pattern;
	}

	public void setPattern(JSONObject pattern) {
		this.pattern = pattern;
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();
		out.put("pattern", this.pattern);
		return out;
	}
}
