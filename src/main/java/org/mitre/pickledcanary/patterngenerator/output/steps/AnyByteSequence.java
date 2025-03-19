
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

import org.json.JSONObject;

/**
 * A step in the pattern that matches a certain number of bytes regardless of the bytes' values.
 */
public class AnyByteSequence extends StepBranchless {

	private int min;
	private int max;
	private Integer interval = 1;

	/**
	 * Creates an AnyByteSequence.
	 * @param min minimum number of bytes to match regardless of value; must be nonnegative
	 * @param max maximum number of bytes to match regardless of value; must be greater than min
	 * @param interval number of bytes stepped in each iteration; must be nonnegative; set to 1 if
	 * value is null
	 */
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
		if (maxInput < minInput || minInput < 0 || intervalInput != null && intervalInput <= 0) {
			throw new IllegalArgumentException(String.format(
					"ANY_BYTES min and max must be nonnegative, min must be smaller than or equal to max, and interval must be positive: `%s`",
					toStringHelper(minInput, maxInput, intervalInput)));
		} else if (intervalInput != null && (intervalInput > (maxInput - minInput))
				&& (maxInput != minInput)) {
			throw new IllegalArgumentException(
					String.format("ANY_BYTES interval must be less than (max-min): `%s`",
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

	@Override
	public String toString() {
		return toStringHelper(this.min, this.max, this.interval);
	}

	private String toStringHelper(int minParam, int maxParam, Integer intervalParam) {
		if (intervalParam == null) {
			return "ANY_BYTES{" + minParam + "," + maxParam + "}";
		}
		return "ANY_BYTES{" + minParam + "," + maxParam + "," + intervalParam + "}";
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
		AnyByteSequence other = (AnyByteSequence) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType) && this.min == other.min &&
			this.max == other.max && this.interval == other.interval;
	}

	@Override
	public int hashCode() {
		return Objects.hash(stepType, min, max, interval);
	}
}
