
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.utils;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;

public class OperandRepresentation implements Comparable<OperandRepresentation> {

	private final List<Integer> mask;
	private final List<Integer> value;

	/**
	 * One mask and binary representation of the operand in {@link LookupTable}.
	 *
	 * @param mask  the mask of the operand, as a decimal (use more than one byte if
	 *              decimal > 255)
	 * @param value the value of the operand, as a decimal (use more than one byte
	 *              if decimal > 255)
	 */
	public OperandRepresentation(List<Integer> mask, List<Integer> value) {
		if (mask == null) {
			throw new IllegalArgumentException("Mask must not be null");
		}
		if (value == null) {
			throw new IllegalArgumentException("Value must not be null");
		}
		if (mask.size() != value.size()) {
			throw new IllegalArgumentException("Mask and Value must be the same length");
		}
		this.mask = mask;
		this.value = value;
	}

	/**
	 * Get the JSON representation of the mask.
	 *
	 * @return JSON
	 */
	public JSONArray getJsonMask() {
		return new JSONArray(mask);
	}

	/**
	 * Get the JSON representation of the value.
	 *
	 * @return JSON
	 */
	public JSONArray getJsonValue() {
		return new JSONArray(value);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((mask == null) ? 0 : mask.hashCode());
		result = prime * result + ((value == null) ? 0 : value.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		OperandRepresentation other = (OperandRepresentation) obj;
		if (!mask.equals(other.mask)) {
			return false;
		}
		return value.equals(other.value);
	}

	public boolean matches(List<Integer> needle) {
		int len = this.mask.size();
		List<Integer> needleMasked = new ArrayList<>(len);
		for (int i = 0; i < len; i++) {
			needleMasked.add(needle.get(i) & this.mask.get(i));
		}
		return needleMasked.equals(this.value);
	}

	@Override
	public String toString() {
		return "{M:" + this.mask.toString() + ", V:" + this.value.toString() + "}";
	}

	@Override
	public int compareTo(OperandRepresentation o) {
		var out = Integer.compare(this.mask.size(), o.mask.size());
		if (out != 0) {
			return out;
		}

		for (var i = 0; i < this.mask.size(); i++) {
			out = this.mask.get(i).compareTo(o.mask.get(i));
			if (out != 0) {
				return out;
			}
		}
		for (var i = 0; i < this.value.size(); i++) {
			out = this.value.get(i).compareTo(o.value.get(i));
			if (out != 0) {
				return out;
			}
		}
		return 0;
	}
}
