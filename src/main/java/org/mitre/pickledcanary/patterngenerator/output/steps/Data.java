
// Copyright (C) 2024 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.List;

import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;
import org.mitre.pickledcanary.patterngenerator.output.utils.LookupTable;
import org.mitre.pickledcanary.search.SavedData;
import org.mitre.pickledcanary.util.JsonSerializable;

import ghidra.program.model.mem.MemBuffer;

public interface Data extends JsonSerializable {

	/**
	 * Replace temporary table key with the actual table key.
	 * 
	 * @param tables
	 */
	public void resolveTableIds(AllLookupTables tables);

	/**
	 * Execute this lookup on the given MemBuffer at offset sp using the given tables.
	 * <p>
	 * There's a good chance you want to use doLookupAndCheck instead of this method
	 */
	public LookupResults doLookup(MemBuffer input, int sp, List<LookupTable> tables);

	/**
	 * Given results from a doLookup, see if they conflict with the given existing SavedData.
	 * <p>
	 * Conflicts are defined as cases where a given var_id has different values in the toCheck
	 * results and the existing saved data (e.g.: Q1 was r0 in existing, but the new toCheck results
	 * say Q1 is r3. That's a conflict)
	 * <p>
	 * If there's a conflict, returns null, otherwise returns a new SavedData which contains the
	 * information from both toCheck and existing.
	 */
	public SavedData doCheck(LookupResults toCheck, SavedData existing);

	/**
	 * Do both a doLookup and a doCheck (see their descriptions for more info)
	 */
	public LookupAndCheckResult doLookupAndCheck(MemBuffer input, int sp, List<LookupTable> tables,
			SavedData existing);
}