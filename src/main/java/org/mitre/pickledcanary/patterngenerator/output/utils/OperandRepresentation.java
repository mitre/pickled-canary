
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.utils;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;

public class OperandRepresentation {

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
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		OperandRepresentation other = (OperandRepresentation) obj;
		if (mask == null) {
			if (other.mask != null)
				return false;
		} else if (!mask.equals(other.mask)) {
			return false;
		}
		if (value == null) {
			return other.value == null;
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

	public String toString() {
		return "{M:" + this.mask.toString() + ", V:" + this.value.toString() + "}";
	}
}
