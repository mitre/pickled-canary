
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.List;
import java.util.NoSuchElementException;

import org.json.JSONObject;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;

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
}