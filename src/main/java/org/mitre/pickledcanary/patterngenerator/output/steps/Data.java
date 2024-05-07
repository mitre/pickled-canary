
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.List;

import org.json.JSONObject;
import org.mitre.pickledcanary.patterngenerator.output.utils.LookupTable;
import org.mitre.pickledcanary.search.SavedData;

import ghidra.program.model.mem.MemBuffer;
import org.mitre.pickledcanary.util.JsonSerializable;


public interface Data extends JsonSerializable {
	List<Integer> mask();

	//LookupResults doLookup(MemBuffer input, int sp, List<LookupTable> tables);
	//SavedData doCheck(LookupResults toCheck, SavedData existing);
	//LookupAndCheckResult doLookupAndCheck(MemBuffer input, int sp, List<LookupTable> tables, SavedData existing);
}