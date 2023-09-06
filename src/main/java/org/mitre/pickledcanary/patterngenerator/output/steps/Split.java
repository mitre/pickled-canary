
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import org.json.JSONObject;

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

	public void setDest1(int dest1) {
		this.dest1 = dest1;
	}

	public void setDest2(int dest2) {
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
}
