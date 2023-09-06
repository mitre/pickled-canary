
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import org.json.JSONObject;

public class AnyByteSequence extends StepBranchless {

	private int min;
	private int max;
	private Integer interval = 1;

	public AnyByteSequence(int min, int max, Integer interval) {
		super(StepType.ANYBYTESEQUENCE, null);
		this.setMinMaxInterval(min, max, interval);
	}

	public AnyByteSequence(int min, int max, Integer interval, String note) {
		super(StepType.ANYBYTESEQUENCE, note);
		this.setMinMaxInterval(min, max, interval);
	}

	public void setMin(int value) {
		verifyInputs(value, this.max, this.interval);
		this.min = value;
	}

	public void setMax(int value) {
		verifyInputs(this.min, value, this.interval);
		this.max = value;
	}

	public void setInterval(Integer value) {
		verifyInputs(this.min, this.max, value);
		this.interval = value;
	}

	public void setMinMaxInterval(int min, int max, Integer interval) {
		verifyInputs(min, max, interval);
		this.min = min;
		this.max = max;
		if (interval == null) {
			this.interval = 1;
		} else {
			this.interval = interval;
		}
	}

	private void verifyInputs(int minInput, int maxInput, Integer intervalInput) {
		if (maxInput < minInput || minInput < 0 || intervalInput != null && intervalInput < 0) {
			throw new RuntimeException(String.format(
					"ANY_BYTES min, max and interval must be nonnegative, and min must be smaller than or equal to max: `%s`",
					toStringHelper(minInput, maxInput, intervalInput)));
		} else if (intervalInput != null && (intervalInput > (maxInput - minInput)) && (maxInput != minInput)) {
			throw new RuntimeException(String.format("ANY_BYTES interval must be less than (max-min): `%s`",
					toStringHelper(minInput, maxInput, intervalInput)));
		}
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();
		out.put("min", this.min);
		out.put("max", this.max);
		if (this.interval != null) {
			out.put("interval", this.interval);
		}
		return out;
	}

	public int getMin() {
		return this.min;
	}

	public int getMax() {
		return this.max;
	}

	public Integer getInterval() {
		return this.interval;
	}

	public String toString() {
		return toStringHelper(this.min, this.max, this.interval);
	}

	private String toStringHelper(int minParam, int maxParam, Integer intervalParam) {
		if (intervalParam == null) {
			return "ANY_BYTES{" + minParam + "," + maxParam + "}";
		}
		return "ANY_BYTES{" + minParam + "," + maxParam + "," + intervalParam + "}";
	}
}
