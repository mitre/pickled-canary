
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

public class SplitMulti extends Step {

	private final List<Integer> dests;

	public SplitMulti(int dest1) {
		super(StepType.SPLITMULTI, null);
		this.dests = new ArrayList<>();
		this.dests.add(dest1);
	}

	public SplitMulti(int dest1, String note) {
		super(StepType.SPLITMULTI, note);
		this.dests = new ArrayList<>();
		this.dests.add(dest1);
	}

	public void addDest(int dest) {
		this.dests.add(dest);
	}

	public List<Integer> getDests() {
		return this.dests;
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();
		JSONArray dests_json = new JSONArray();
		for (Integer d : this.dests) {
			dests_json.put(d);
		}
		out.put("dests", dests_json);
		return out;
	}

	@Override
	public void increment(int amount, int threshold) {
		for (int i = 0; i < this.dests.size(); i++) {
			int val = this.dests.get(i);
			if (val >= threshold) {
				val += amount;
				this.dests.set(i, val);
			}
		}
	}
}
