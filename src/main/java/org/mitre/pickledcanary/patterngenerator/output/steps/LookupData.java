
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;
import org.mitre.pickledcanary.patterngenerator.output.utils.BitArray;
import org.mitre.pickledcanary.patterngenerator.output.utils.LookupTable;
import org.mitre.pickledcanary.search.SavedData;
import org.mitre.pickledcanary.util.PCBytes;

import ghidra.program.model.mem.MemBuffer;

/**
 * Holds encodings for a given mask of an assembly instruction.
 * @param mask the mask for the assembly encodings
 * @param choices map from value after opcode mask to concrete instruction encodings
 */
public record LookupData(
		byte[] mask,
		HashMap<ByteArrayWrapper, InstructionEncoding> choices) implements Data {

	public LookupData(byte[] mask) {
		this(mask, new HashMap<>());
	}

	public boolean hasChoice(byte[] value) {
		return choices.containsKey(new ByteArrayWrapper(value));
	}

	public InstructionEncoding getChoice(byte[] value) {
		return choices.get(new ByteArrayWrapper(value));
	}

	public void putChoice(byte[] value, InstructionEncoding ie) {
		choices.put(new ByteArrayWrapper(value), ie);
	}

	@Override
	public void combine(Data that) {
		if (that instanceof LookupData other) {
			assert Arrays.equals(mask, other.mask);

			for (ByteArrayWrapper choice : other.choices.keySet()) {
				choices.put(choice, other.choices.get(choice));
			}
		}
	}

	@Override
	public void resolveTableIds(AllLookupTables tables) {
		for (InstructionEncoding ie : choices.values()) {
			ie.resolveTableIds(tables);
		}
	}

	@Override
	public JSONObject getJson() {
		List<InstructionEncoding> sorted = new ArrayList<>(choices.values());
		Collections.sort(sorted);

		JSONArray arr = new JSONArray();
		for (InstructionEncoding ie : sorted) {
			arr.put(ie.getJson());
		}

		JSONObject out = new JSONObject();
		out.put("type", "MaskAndChoose");

		out.put("mask", PCBytes.integerList(mask));
		out.put("choices", arr);
		return out;
	}

	@Override
	public LookupResults doLookup(MemBuffer input, int sp, List<LookupTable> tables) {
		byte[] data = new byte[this.mask.length];

		if (input.getBytes(data, sp) < this.mask.length) {
			return null;
		}
		byte[] maskedData = this.getMasked(data, this.mask);

		BitArray dataBitArray = null;

		choices: for (InstructionEncoding ie : choices.values()) { // TODO: refactor this
			if (ie.getValue().equals(maskedData)) {

				if (dataBitArray == null) {
					dataBitArray = this.readToBitArray(input, sp, this.mask.length);
				}

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
					}
					else if (o.type == OperandMeta.TypeOfOperand.Scalar) {
						ScalarOperandMeta oo = (ScalarOperandMeta) o;

						ConcreteOperand out;
						if (oo.varId.charAt(0) == ':') {
							// A scalar field which starts with a ":" is taken
							// to be a computed expression resulting in an
							// address (represented as an SP value)
							long x = LookupDataExpressionSolver.computeExpression(
								oo.getExpression(), input, ie.getContext(), sp,
								this.mask.length);
							out = new ConcreteOperandAddress(oo.varId.substring(1), x);
						}
						else {
							BitArray operandData = dataBitArray.trimToMask(new BitArray(oo.mask));
							out = new ConcreteOperandScalar(oo.varId, operandData);
						}
						concreteOperands.add(out);
					}
					else {
						throw new UnsupportedOperationException("Unknown operand type: " + o);
					}
				}
				return new LookupResults(maskedData.length, concreteOperands);
			}
		}

		return null;
	}

	@Override
	public SavedData doCheck(LookupResults toCheck, SavedData existing) {
		SavedData localSaved = new SavedData(existing);
		for (ConcreteOperand o : toCheck.getOperands()) {
			if (!localSaved.addOrFail(o)) {
				return null;
			}
		}
		return localSaved;
	}

	@Override
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

	private BitArray readToBitArray(MemBuffer input, int sp, int len) {
		byte[] bytes = new byte[len];
		int len_read = input.getBytes(bytes, sp);
		if (len_read < len) {
			return null;
		}
		return new BitArray(bytes);
	}

	private byte[] getMasked(byte[] base, byte[] maskParam) {
		byte[] maskedData = base.clone();

		for (int i = 0; i < maskParam.length; i++) {
			maskedData[i] &= maskParam[i];
		}
		return maskedData;
	}

	@Override
	public String toString() {
		return "LookupData[mask=" + new ByteArrayWrapper(this.mask) + ", choices=" +  this.choices.toString() + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 23;
		result = prime * result + Arrays.hashCode(mask);
		result = prime * result + Objects.hash(choices);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		LookupData other = (LookupData) obj;
		return Objects.equals(choices, other.choices) && Arrays.equals(mask, other.mask);
	}
}
