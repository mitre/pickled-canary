
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONObject;

/**
 * A lookup table for matching operands to their binary representations. See B
 * in JavaDoc in {@link AllLookupTables}.
 */
public class LookupTable implements Comparable<LookupTable>{

	// the table - map from operand to the OperandTable
	private final HashMap<String, OperandTable> operandTables;

	/**
	 * Constructor for LookupTables.
	 * 
	 * @param operand the assembly operand
	 * @param mask    the mask of the operand, as a decimal (use more than one byte
	 *                if decimal > 255)
	 * @param value   the value of the operand, as a decimal (use more than one byte
	 *                if decimal > 255)
	 */
	public LookupTable(String operand, List<Integer> mask, List<Integer> value) {
		operandTables = new HashMap<>();
		put(operand, mask, value);
	}

	/**
	 * Put data in the tables.
	 * 
	 * @param operand the operand to put in the table
	 * @param mask    the mask of the operand, as a decimal (use more than one byte
	 *                if decimal > 255)
	 * @param value   the value of the operand, as a decimal (use more than one byte
	 *                if decimal > 255)
	 */
	public void put(String operand, List<Integer> mask, List<Integer> value) {
		if (operandTables.containsKey(operand)) {
			operandTables.get(operand).add(mask, value);
		} else {
			operandTables.put(operand, new OperandTable(mask, value));
		}
	}

	/**
	 * Get the JSON representation of a LookupTable.
	 * 
	 * @return JSON
	 */
	public JSONObject getJson() {
		JSONObject out = new JSONObject();
		for (String operand : operandTables.keySet()) {
			out.put(operand, operandTables.get(operand).getJson());
		}
		return out;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((operandTables == null) ? 0 : operandTables.hashCode());
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
		LookupTable other = (LookupTable) obj;
		if (operandTables == null) {
			return other.operandTables == null;
		}
		return operandTables.equals(other.operandTables);
	}

	public String lookup(List<Integer> needle) {
		for (Map.Entry<String, OperandTable> entry : operandTables.entrySet()) {
			if (entry.getValue().lookup(needle)) {
				return entry.getKey();
			}
		}
		return null;
	}

	public String toString() {
		StringBuilder out = new StringBuilder("LookupTable: ");
		for (Map.Entry<String, OperandTable> entry : operandTables.entrySet()) {
			out.append("\n\t").append(entry.getKey()).append("=").append(entry.getValue().toString());
		}
		return out.toString();
	}

	@Override
	public int compareTo(LookupTable o) {
		var out = Integer.valueOf(operandTables.size()).compareTo(o.operandTables.size());
		if (out != 0) {
			return out;
		}

		var keys = new ArrayList<String>(operandTables.keySet());
		Collections.sort(keys);
		var oKeys = new ArrayList<String>(o.operandTables.keySet());
		Collections.sort(oKeys);
		for (var i = 0; i < keys.size(); i++) {
			out = keys.get(i).compareTo(oKeys.get(i));
			if (out != 0) {
				return out;
			}
		}

		for (String key : keys) {
			out = this.operandTables.get(key).compareTo(o.operandTables.get(key));
			if (out != 0) {
				return out;
			}
		}
		return 0;
	}
}
