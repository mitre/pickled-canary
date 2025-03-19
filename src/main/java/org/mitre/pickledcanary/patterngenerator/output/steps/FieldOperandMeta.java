
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;

import org.json.JSONObject;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;

/**
 * Represents a pointer to a set of operand choices for a given mask and wildcard in the output json.
 */
public class FieldOperandMeta extends OperandMeta {

	private final String tableKey;
	private int resolvedTableKey = -1; // table_id field in json

	/**
	 * Field operand type
	 *
	 * @param mask      Mask of a specific operand
	 * @param tableKey  temporary table key
	 * @param varId     variable ID (Q1) of operand
	 */
	public FieldOperandMeta(List<Integer> mask, String tableKey, String varId) {
		super(TypeOfOperand.Field, mask, varId);
		this.tableKey = tableKey;
	}

	/**
	 * Replace temporary table key with the actual table key.
	 *
	 * @param tables
	 */
	public void resolveTableIds(AllLookupTables tables) {
		resolvedTableKey = tables.lookupTable(tableKey);
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();
		out.put("table_id", resolvedTableKey == -1 ? tableKey : resolvedTableKey);
		return out;
	}

	public int getResolvedTableKey() {
		if (resolvedTableKey == -1) {
			throw new NoSuchElementException("Table Key not yet resolved!");
		}
		return this.resolvedTableKey;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Objects.hash(resolvedTableKey, tableKey);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj) || getClass() != obj.getClass()) {
			return false;
		}
		FieldOperandMeta other = (FieldOperandMeta) obj;
		return resolvedTableKey == other.resolvedTableKey &&
			Objects.equals(tableKey, other.tableKey);
	}
}