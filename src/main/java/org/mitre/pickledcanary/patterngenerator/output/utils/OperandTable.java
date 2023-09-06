
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.utils;

import java.util.HashSet;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * A table matching operands to their binary representations. See C in JavaDoc
 * in {@link AllLookupTables}.
 */
public class OperandTable {

	// The binary representations (along with masks) for the operand of this table
	private final HashSet<OperandRepresentation> reps;

	/**
	 * Constructor of OperandTable.
	 * 
	 * @param mask  the mask of the operand, as a decimal (use more than one byte if
	 *              decimal > 255)
	 * @param value the value of the operand, as a decimal (use more than one byte
	 *              if decimal > 255)
	 */
	public OperandTable(List<Integer> mask, List<Integer> value) {
		reps = new HashSet<>();
		add(mask, value);
	}

	/**
	 * Add a mask and binary representation to the table.
	 * 
	 * @param mask  the mask of the operand, as a decimal (use more than one byte if
	 *              decimal > 255)
	 * @param value the value of the operand, as a decimal (use more than one byte
	 *              if decimal > 255)
	 */
	public void add(List<Integer> mask, List<Integer> value) {
		reps.add(new OperandRepresentation(mask, value));
	}

	/**
	 * Get the JSON representation of this table.
	 * 
	 * @return JSON
	 */
	public JSONArray getJson() {
		JSONArray out = new JSONArray();
		for (OperandRepresentation or : reps) {
			JSONObject o = new JSONObject();
			o.put("mask", or.getJsonMask());
			o.put("value", or.getJsonValue());
			out.put(o);
		}
		return out;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((reps == null) ? 0 : reps.hashCode());
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
		OperandTable other = (OperandTable) obj;
		if (reps == null) {
			return other.reps == null;
		}
		return reps.equals(other.reps);
	}

	public boolean lookup(List<Integer> needle) {
		for (OperandRepresentation x : this.reps) {
			if (x.matches(needle)) {
				return true;
			}
		}
		return false;
	}

	public String toString() {
		StringBuilder out = new StringBuilder("Operand Table:");
		for (OperandRepresentation x : this.reps) {
			out.append("\n\t").append(x.toString());
		}
		return out.toString();
	}
}
