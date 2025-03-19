
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;
import org.mitre.pickledcanary.patterngenerator.output.utils.LookupTable;
import org.mitre.pickledcanary.search.SavedData;

import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.mem.MemBuffer;

/**
 * Represents an assembled assembly instruction of a Pickled Canary pattern. Instruction can be
 * valid assembly instruction or an instruction with Pickled Canary wildcards.
 */
public class LookupStep extends StepBranchless {

	private final String instructionText;
	private final int lineNumber;
	private final int charPosition;
	private final HashMap<List<Integer>, Data> data; // map from opcode mask to data (encodings)
	private RegisterValue outputContext;

	public LookupStep(String instructionText, int lineNumber, int charPosition) {
		this(instructionText, lineNumber, charPosition, null, null);
	}

	/**
	 * Creates a LookupStep.
	 * @param instructionText the instruction text that the user entered
	 * @param lineNumber line number of the instruction in the user pattern
	 * @param charPosition the position of the first character of the instruction in the line
	 * @param note any comments
	 * @param outputContext context produced by the encodings
	 */
	public LookupStep(String instructionText, int lineNumber, int charPosition, String note, RegisterValue outputContext) {
		super(StepType.LOOKUP, note);
		this.instructionText = instructionText;
		this.lineNumber = lineNumber;
		this.charPosition = charPosition;
		this.data = new HashMap<>();
		this.outputContext = outputContext;
	}

	public String getInstructionText() {
		return instructionText;
	}

	public int getLineNumber() {
		return lineNumber;
	}

	public int getCharPosition() {
		return charPosition;
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
	 * Adds the encodings of another LookupStep into this LookupStep.
	 * @param that another LookupStep
	 */
	public void combine(LookupStep that) {
		for (List<Integer> mask : that.data.keySet()) {
			if (!data.containsKey(mask)) {
				data.put(mask, that.data.get(mask));
			} else {
				data.get(mask).combine(that.data.get(mask));
			}
		}
	}

	public RegisterValue getOutputContext() {
		return outputContext;
	}

	public void setOutputContext(RegisterValue outputContext) {
		this.outputContext = outputContext;
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
	 * @param existing Existing SavedData to check lookups against. If new variables conflict
	 *                 against these, the result will not be included in the return value.
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

	@Override
	public String toString() {
		return "LookupStep(instruction: \"" + this.instructionText + "\" data: "
				+ this.data.toString() + ")";
	}

	public boolean isEmpty() {
		return this.data.isEmpty();
	}

	public LookupStep copy() {
		return new LookupStep(instructionText, lineNumber, charPosition, note, outputContext);
	}

	@Override
	public boolean equals(Object o) {
		// self check
		if (this == o) {
			return true;
		}
		// null check
		// type check and cast
		if ((o == null) || (getClass() != o.getClass())) {
			return false;
		}
		LookupStep other = (LookupStep) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType) && this.data.equals(other.data);
	}

	@Override
	public int hashCode() {
		return Objects.hash(stepType, data);
	}
}
