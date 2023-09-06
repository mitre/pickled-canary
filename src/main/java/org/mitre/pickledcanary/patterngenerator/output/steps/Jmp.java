
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import org.json.JSONObject;

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
}
