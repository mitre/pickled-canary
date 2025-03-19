
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

import org.json.JSONObject;

/**
 * A set of steps in the pattern that should not be matched.
 */
public class NegativeLookahead extends StepBranchless {

	private final JSONObject pattern;

	public NegativeLookahead(JSONObject pattern) {
		super(StepType.NEGATIVELOOKAHEAD, null);
		this.pattern = pattern;
	}

	public NegativeLookahead(JSONObject pattern, String note) {
		super(StepType.NEGATIVELOOKAHEAD, note);
		this.pattern = pattern;
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();
		out.put("pattern", this.pattern);
		return out;
	}

	@Override
	public String toString() {
		return "NEGATIVE LOOK AHEAD Pattern: " + pattern.toString();
	}

	@Override
	/**
	 * THIS ISN'T GREAT! It compares the inner patterns as JSONObjects, which will almost always say
	 * they are different even if the content is the same!
	 */
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
		NegativeLookahead other = (NegativeLookahead) o;
		// field comparison
		//TODO: JSONObject doesn't seem to have equals and hashcode implementations
		return Objects.equals(this.stepType, other.stepType) && this.pattern.equals(other.pattern);
	}

	@Override
	public int hashCode() {
		return Objects.hash(stepType, pattern);
	}
}
