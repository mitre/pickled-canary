
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import org.json.JSONObject;

public abstract class Step {

	public enum StepType {
		BYTE, MASKEDBYTE, MATCH, JMP, SPLIT, SPLITMULTI, SAVE, ANYBYTE, ANYBYTESEQUENCE, LOOKUP, NEGATIVELOOKAHEAD,
		SAVESTART, LABEL
	}

	protected final StepType stepType;
	protected final String note;

	public Step(StepType stepType, String note) {
		this.stepType = stepType;
		this.note = note;
	}

	public JSONObject getJson() {
		JSONObject out = new JSONObject();
		if (this.note != null) {
			out.put("note", this.note);
		}
		out.put("type", this.stepType);
		return out;
	}

	/**
	 * If this step can jump or branch to another step other than the next step
	 * (fallthrough), increment the/those destination(s) by 'amount' if the
	 * destination is greater than or equal to 'threshold'
	 * 
	 * @param amount
	 * @param threshold
	 */
	public abstract void increment(int amount, int threshold);

	public void increment(int amount) {
		this.increment(amount, 0);
	}
}
