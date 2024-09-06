
// Copyright (C) 2024 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;
import org.mitre.pickledcanary.patterngenerator.output.utils.LookupTable;
import org.mitre.pickledcanary.search.SavedData;

import ghidra.program.model.mem.MemBuffer;

public class LookupStep extends StepBranchless {

	private final HashMap<List<Integer>, Data> data; // map from opcode mask to data

	public LookupStep() {
		super(StepType.LOOKUP, null);
		this.data = new HashMap<>();
	}

	public LookupStep(String note) {
		super(StepType.LOOKUP, note);
		this.data = new HashMap<>();
	}

	public boolean hasMask(List<Integer> mask) {
		return data.containsKey(mask);
	}

	public Data getData(List<Integer> mask) {
		return data.get(mask);
	}

	public void putData(List<Integer> mask, Data d) {
		data.put(mask, d);
	}

	/**
	 * Replace temporary table key with the actual table key.
	 * 
	 * @param tables
	 */
	public void resolveTableIds(AllLookupTables tables) {
		for (Data d : data.values()) {
			d.resolveTableIds(tables);
		}
	}

	@Override
	public JSONObject getJson() {
		JSONArray arr = new JSONArray();
		for (Data d : data.values()) {
			arr.put(d.getJson());
		}

		JSONObject out = super.getJson();
		out.put("data", arr);
		return out;
	}

	public List<Data> getAllData() {
		return new LinkedList<>(this.data.values());
	}

	/**
	 * Loop over all our internal data doing a lookup on each and return the combined results
	 * 
	 * @param input
	 * @param sp
	 * @param tables
	 * @param existing
	 *            Existing SavedData to check lookups against. If new variables conflict against
	 *            these, the result will not be included in the return value.
	 * @return
	 */
	public List<LookupAndCheckResult> doLookup(MemBuffer input, int sp, List<LookupTable> tables,
			SavedData existing) {

		List<LookupAndCheckResult> out = new ArrayList<>(this.data.size());

		for (Data d : this.getAllData()) {
			LookupAndCheckResult result = d.doLookupAndCheck(input, sp, tables, existing);
			if (result != null) {
				out.add(result);
			}
		}
		return out;
	}

	public String toString() {
		return "LookupStep(data: " + this.data.toString() + ")";
	}

	public boolean isEmpty() {
		return this.data.isEmpty();
	}
}
