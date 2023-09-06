
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.List;

import org.json.JSONObject;
import org.mitre.pickledcanary.patterngenerator.output.utils.LookupTable;
import org.mitre.pickledcanary.search.SavedData;

import ghidra.program.model.mem.MemBuffer;

public abstract class Data {

	public enum DataType {
		MaskAndChoose
	}

	protected final DataType type;
	protected final List<Integer> mask; // opcode mask

	public Data(DataType type, List<Integer> mask) {
		this.type = type;
		this.mask = mask;
	}

	public DataType getType() {
		return type;
	}

	public List<Integer> getMask() {
		return mask;
	}

	abstract JSONObject getJson();

	abstract public LookupResults doLookup(MemBuffer input, int sp, List<LookupTable> tables);

	abstract public SavedData doCheck(LookupResults toCheck, SavedData existing);

	abstract public LookupAndCheckResult doLookupAndCheck(MemBuffer input, int sp, List<LookupTable> tables,
			SavedData existing);

	abstract public String toString();
}
