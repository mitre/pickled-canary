
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mitre.pickledcanary.patterngenerator.UnsupportedExpressionException;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;
import org.mitre.pickledcanary.patterngenerator.output.utils.BitArray;
import org.mitre.pickledcanary.patterngenerator.output.utils.LookupTable;
import org.mitre.pickledcanary.search.SavedData;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

/**
 *
 * @param choices map from value after opcode mask to concrete instruction encodings
 * @param mask
 */
public record LookupData(
		List<Integer> mask,
		HashMap<List<Integer>, InstructionEncoding> choices
) implements Data {

	public LookupData(List<Integer> mask) {
		this(mask, new HashMap<>());
	}

	public boolean hasChoice(List<Integer> value) {
		return choices.containsKey(value);
	}

	public InstructionEncoding getChoice(List<Integer> value) {
		return choices.get(value);
	}

	public void putChoice(List<Integer> value, InstructionEncoding ie) {
		choices.put(value, ie);
	}

	/**
	 * Replace temporary table key with the actual table key.
	 * 
	 * @param tables
	 */
	public void resolveTableIds(AllLookupTables tables) {
		for (InstructionEncoding ie : choices.values()) {
			ie.resolveTableIds(tables);
		}
	}

	public JSONObject getJson() {
		JSONArray arr = new JSONArray();
		for (InstructionEncoding ie : choices.values()) {
			arr.put(ie.getJson());
		}

		JSONObject out = new JSONObject();
		out.put("type", "MaskAndChoose");
		out.put("mask", mask);
		out.put("choices", arr);
		return out;
	}

	/**
	 * Execute this lookup on the given MemBuffer at offset sp using the given
	 * tables.
	 * <p>
	 * There's a good chance you want to use doLookupAndCheck instead of this method
	 */
	public LookupResults doLookup(MemBuffer input, int sp, List<LookupTable> tables) {
		List<Integer> data = this.readToList(input, sp, this.mask.size());
		if (data == null) {
			return null;
		}
		List<Integer> maskedData = this.getMasked(data, this.mask);

		BitArray dataBitArray = this.readToBitArray(input, sp, this.mask.size());

		choices: for (InstructionEncoding ie : choices.values()) { // TODO: refactor this
			if (ie.getValue().equals(maskedData)) {
				List<ConcreteOperand> concreteOperands = new ArrayList<>(ie.getOperands().size());
				for (OperandMeta o : ie.getOperands()) {
					if (o instanceof FieldOperandMeta oo) {

						BitArray operandData = dataBitArray.trimToMask(new BitArray(oo.mask));
						int tableIdx = oo.getResolvedTableKey();
						LookupTable x = tables.get(tableIdx);
						String fieldName = x.lookup(operandData.toIntList());

						if (fieldName == null) {
							continue choices;
						}
						concreteOperands.add(new ConcreteOperandField(oo.varId, fieldName));
					} else if (o.type == OperandMeta.TypeOfOperand.Scalar) {
						ScalarOperandMeta oo = (ScalarOperandMeta) o;

						ConcreteOperand out;
						if (oo.varId.charAt(0) == ':') {
							// A scalar field which starts with a ":" is taken
							// to be a computed expression resulting in an
							// address (represented as an SP value)
							long x = LookupDataExpressionSolver.computeExpression(oo.getExpression(), input, sp,
									this.mask.size());
							out = new ConcreteOperandAddress(oo.varId.substring(1), x);
						} else {
							BitArray operandData = dataBitArray.trimToMask(new BitArray(oo.mask));
							out = new ConcreteOperandScalar(oo.varId, operandData);
						}
						concreteOperands.add(out);
					} else {
						throw new UnsupportedOperationException("Unknown operand type: " + o);
					}
				}
				return new LookupResults(maskedData.size(), concreteOperands);
			}
		}

		return null;
	}

	/**
	 * Given results from a doLookup, see if they conflict with the given existing
	 * SavedData.
	 * <p>
	 * Conflicts are defined as cases where a given var_id has different values in
	 * the toCheck results and the existing saved data (e.g.: Q1 was r0 in existing,
	 * but the new toCheck results say Q1 is r3. That's a conflict)
	 * <p>
	 * If there's a conflict, returns null, otherwise returns a new SavedData which
	 * contains the information from both toCheck and existing.
	 */
	public SavedData doCheck(LookupResults toCheck, SavedData existing) {
		SavedData localSaved = new SavedData(existing);
		for (ConcreteOperand o : toCheck.getOperands()) {
			if (!localSaved.addOrFail(o)) {
				return null;
			}
		}
		return localSaved;
	}

	/**
	 * Do both a doLookup and a doCheck (see their descriptions for more info)
	 */
	public LookupAndCheckResult doLookupAndCheck(MemBuffer input, int sp, List<LookupTable> tables,
			SavedData existing) {
		LookupResults result = this.doLookup(input, sp, tables);
		if (result != null) {
			SavedData newSaved = this.doCheck(result, existing);
			if (newSaved != null) {
				return new LookupAndCheckResult(result.getMatchSize(), newSaved);
			}
		}
		return null;
	}

	private List<Integer> readToList(MemBuffer input, int sp, int len) {
		List<Integer> out = new ArrayList<>(len);
		for (int i = 0; i < len; i++) {
			try {
				out.add((int) input.getByte(sp + i));
			} catch (MemoryAccessException e) {
				return null;
			}
		}
		return out;
	}

	private BitArray readToBitArray(MemBuffer input, int sp, int len) {
		byte[] bytes = new byte[len];
		for (int i = 0; i < len; i++) {
			try {
				bytes[i] = input.getByte(sp + i);
			} catch (MemoryAccessException e) {
				return null;
			}
		}
		return new BitArray(bytes);
	}

	private List<Integer> getMasked(List<Integer> base, List<Integer> maskParam) {
		List<Integer> maskedData = new ArrayList<>();
		for (int i = 0; i < maskParam.size(); i++) {
			int rawData = base.get(i);
			maskedData.add(rawData & maskParam.get(i));
		}
		return maskedData;
	}
}
