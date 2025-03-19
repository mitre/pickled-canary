
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mitre.pickledcanary.patterngenerator.output.steps.OperandMeta.TypeOfOperand;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;

/**
 * Represents a concrete instruction encoding.
 */
public class InstructionEncoding implements Comparable<InstructionEncoding> {

	private final ByteArrayWrapper value; // value of encoding after applying opcode mask
	private final List<OperandMeta> operands; // list of operands
	private int[] context = null; // Local context (when required)

	public InstructionEncoding(byte[] value) {
		this.value = new ByteArrayWrapper(value);
		this.operands = new ArrayList<>();
	}

	public void addOperand(OperandMeta ot) {
		operands.add(ot);
	}

	public void addContext(int[] context) {
		this.context = context;
	}

	/**
	 * If an operand in the operands list has the same varId as the operand being passed into this
	 * method, their types and masks should match.
	 *
	 * @param operand operand to be placed in the operands list
	 * @return true if an operand with the same varId exists and their types and masks match; false
	 *         if no operand with same varId exists
	 */
	public boolean matches(OperandMeta operand) {
		for (OperandMeta om : operands) {
			if (operand.varId.equals(om.varId) && operand.type == om.type &&
				operand.mask.equals(om.mask)) {
				return true;

			}
		}
		return false;
	}

	/**
	 * Replace temporary table key with the actual table key.
	 *
	 * @param tables
	 */
	public void resolveTableIds(AllLookupTables tables) {
		for (OperandMeta operandMeta : operands) {
			if (operandMeta.getType() == TypeOfOperand.Field) {
				((FieldOperandMeta) operandMeta).resolveTableIds(tables);
			}
		}
	}

	public JSONObject getJson() {
		JSONArray operandArr = new JSONArray();

		operands.sort(OperandMeta::compareTo);
		for (OperandMeta ot : operands) {
			operandArr.put(ot.getJson());
		}

		JSONObject out = new JSONObject();
		out.put("value", value);
		out.put("operands", operandArr);

		if (context != null) {
			out.put("context", contextToJson(context));
		}

		return out;
	}

	private List<Long> contextToJson(int[] input) {
		List<Long> out = new ArrayList<>(input.length);

		for (int chunk : input) {
			// Sigh
			out.add(Integer.toUnsignedLong(chunk));
		}
		return out;
	}

	public ByteArrayWrapper getValue() {
		return this.value;
	}

	public List<OperandMeta> getOperands() {
		return this.operands;
	}

	public int[] getContext() {
		return this.context;
	}

	@Override
	public String toString() {
		return "InstructionEncoding(value: " + this.value.toString() + ", operands: " +
			this.operands.toString() + ")";
	}

	@Override
	public int compareTo(InstructionEncoding other) {
		int out = this.value.compareTo(other.value);
		if (out != 0) {
			return out;
		}

		out = this.operands.size() - other.operands.size();
		if (out != 0) {
			return out;
		}

		for (var i = 0; i < this.operands.size(); i++) {
			out = this.operands.get(i).compareTo(other.operands.get(i));
			if (out != 0) {
				return out;
			}
		}

		return out;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 17;
		result = prime * result + Arrays.hashCode(context);
		result = prime * result + Objects.hash(operands, value);
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
		InstructionEncoding other = (InstructionEncoding) obj;
		return Arrays.equals(context, other.context) && Objects.equals(operands, other.operands) &&
			Objects.equals(value, other.value);
	}
}
