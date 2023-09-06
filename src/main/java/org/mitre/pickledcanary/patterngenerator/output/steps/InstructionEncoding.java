
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mitre.pickledcanary.patterngenerator.output.steps.OperandMeta.TypeOfOperand;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;

public class InstructionEncoding {

	private final List<Integer> value; // value of encoding after applying opcode mask
	private final List<OperandMeta> operands; // list of operands

	public InstructionEncoding(List<Integer> value) {
		this.value = value;
		this.operands = new ArrayList<>();
	}

	public void addOperand(OperandMeta ot) {
		operands.add(ot);
	}

	/**
	 * If an operand in the operands list has the same varId as the operand being
	 * passed into this method, their types and masks should match.
	 * 
	 * @param operand operand to be placed in the operands list
	 * @return true if an operand with the same varId exists and their types and
	 *         masks match; false if no operand with same varId exists
	 * @throws RuntimeException operand with same varId exists but type or mask
	 *                          don't match
	 */
	public boolean matches(OperandMeta operand) {
		for (OperandMeta om : operands) {
			if (operand.operandId == om.operandId && operand.varId.equals(om.varId)) {
				if (operand.type == om.type && operand.mask.equals(om.mask)) {
					return true;
				}
				throw new RuntimeException("Operands do not match.\n\tVar ID: " + om.varId + "\nOperand 1 type: "
						+ om.type + "\tOperand 1 mask: " + om.mask + "\nOperand 2 type: " + operand.type
						+ "\tOperand 2 mask: " + operand.mask);
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
		for (OperandMeta ot : operands) {
			operandArr.put(ot.getJson());
		}

		JSONObject out = new JSONObject();
		out.put("value", value);
		out.put("operands", operandArr);
		return out;
	}

	public List<Integer> getValue() {
		return this.value;
	}

	public List<OperandMeta> getOperands() {
		return this.operands;
	}

	public String toString() {
		return "InstructionEncoding(value: " + this.value.toString() + ", operands: " + this.operands.toString() + ")";
	}
}
