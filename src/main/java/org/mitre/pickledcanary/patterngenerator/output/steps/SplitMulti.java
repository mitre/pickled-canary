
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * A step that creates multiple branches in a pattern.
 */
public class SplitMulti extends Step {

	private final List<Integer> dests;

	public SplitMulti() {
		super(StepType.SPLITMULTI, null);
		this.dests = new ArrayList<>();
	}

	public SplitMulti(int dest1) {
		this();
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
		JSONArray destsJson = new JSONArray();
		for (Integer d : this.dests) {
			destsJson.put(d);
		}
		out.put("dests", destsJson);
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

	@Override
	public String toString() {
		List<String> strDests = new ArrayList<>();
		for (int dest : dests) {
			strDests.add(String.valueOf(dest));
		}
		return "SPLITMULTI Dests: [" + String.join(",", strDests) + "]";
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
		SplitMulti other = (SplitMulti) o;
		// field comparison
		if (!Objects.equals(this.stepType, other.stepType)) {
			return false;
		}
		if (this.dests.size() != other.dests.size()) {
			return false;
		}
		for (int i = 0; i < this.dests.size(); i++) {
			if (!this.dests.get(i).equals(other.dests.get(i))) {
				return false;
			}
		}
		return true;
	}

	@Override
	public int hashCode() {
		return Objects.hash(stepType, dests);
	}
}
