
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import org.json.JSONArray;

//@formatter:off
/**
 * Container for all lookup tables in JSON output.
 * "tables" field for JSON output.
 * E.g. {"010xx010": {"#0x0":{"val":[[0]],"mask":[[255]]},
 *                    "#0x1":{"val":[[1]],"mask":[[255]]}},
 *       "01xx1000": {"r10":{"val":[[2]],"mask":[[7]]}}
 *      }
 * <p>
 * A. Entire thing above are the tables (tables HashMap below).
 * <p>
 * B. {"#0x0":{"val":[[0]],"mask":[[255]]},
 *     "#0x1":{"val":[[1]],"mask":[[255]]}}
 *    One LookupTable
 * <p>
 * C. "#0x0":{"val":[[0]],"mask":[[255]]}
 *    One OperandTable
 * <p>
 * D. [0] and [255]
 *    One OperandRepresentation
 * <p>
 * E. [{"#0x0":{"val":[[0]],"mask":[[255]]},
 *      "#0x1":{"val":[[1]],"mask":[[255]]}},
 *     {"r10":{"val":[[2]],"mask":[[7]]}}
 *    ]
 *    In JSON file, bitMask keys removed, and dictionary converted to list
 *    Index of list put in table_id field of capture groups
 */
//@formatter:on
public class AllLookupTables {
	// map from bitMask key to LookupTable (A in javadoc above)
	private final HashMap<String, LookupTable> tables;
	// map from bitMask key to hash of the corresponding LookupTable
	// used to determine table_id field in capture groups
	private final HashMap<String, Integer> bitMaskToLookupTableHash;
	// map from LookupTable hash to its index in the list in E (above)
	// used to determine table_id field in capture groups
	private final HashMap<Integer, Integer> lookupTableHashToOutIdx;

	public AllLookupTables() {
		tables = new HashMap<>();
		bitMaskToLookupTableHash = new HashMap<>();
		lookupTableHashToOutIdx = new HashMap<>();
	}

	/**
	 * Put data in the tables.
	 *
	 * @param bitMask binary string of value with x's replacing where mask is 1
	 * @param operand the operand to put in the table
	 * @param mask    the mask of the operand, as a decimal (use more than one byte
	 *                if decimal > 255)
	 * @param value   the value of the operand, as a decimal (use more than one byte
	 *                if decimal > 255)
	 */
	public void put(String bitMask, String operand, List<Integer> mask, List<Integer> value) {
		if (tables.containsKey(bitMask)) {
			tables.get(bitMask).put(operand, mask, value);
		} else {
			tables.put(bitMask, new LookupTable(operand, mask, value));
		}
	}

	private void populateStuff() {
		for (String key : tables.keySet()) {
			bitMaskToLookupTableHash.put(key, tables.get(key).hashCode());
		}
		ArrayList<LookupTable> noDupTables = new ArrayList<>(new HashSet<>(tables.values()));
		for (int i = 0; i < noDupTables.size(); i++) {
			lookupTableHashToOutIdx.put(noDupTables.get(i).hashCode(), i);
		}
	}

	/**
	 * Get the index of a table given the table's bitMask key. Used by capture
	 * groups for converting from A to E.
	 *
	 * @param bitMask bitMask key of the table to retrieve
	 * @return index of table in the tables
	 */
	public int lookupTable(String bitMask) {
		try {
			return lookupTableHashToOutIdx.get(bitMaskToLookupTableHash.get(bitMask));
		} catch (NullPointerException e) {
			this.populateStuff();
			return lookupTableHashToOutIdx.get(bitMaskToLookupTableHash.get(bitMask));
		}
	}

	/**
	 * Get the JSON representation of the tables.
	 *
	 * @return JSON
	 */
	public JSONArray getJson() {
		List<LookupTable> tablesOut = this.getPatternTables();
		JSONArray out = new JSONArray();
		for (LookupTable t : tablesOut) {
			out.put(t.getJson());
		}
		return out;
	}

	/**
	 * Get the Pattern representation of the tables.
	 *
	 */
	public List<LookupTable> getPatternTables() {
		if (bitMaskToLookupTableHash.size() == 0) {
			this.populateStuff();
		}
		ArrayList<LookupTable> noDupTables = new ArrayList<>(new HashSet<>(tables.values()));
		return new ArrayList<>(noDupTables);
	}
}
