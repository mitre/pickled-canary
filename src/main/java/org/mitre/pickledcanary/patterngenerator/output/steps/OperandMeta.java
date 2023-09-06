
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.List;

import org.json.JSONObject;

/**
 * Represents operand choices for wildcards in the output json.
 */
public abstract class OperandMeta {

	public enum TypeOfOperand {
		Field, Scalar
	}

	protected final TypeOfOperand type;
	protected final List<Integer> mask;
	protected final String varId;
	protected final int operandId;

	/**
	 * OperandMeta
	 * 
	 * @param type      TypeOfOperand
	 * @param mask      mask of an operand
	 * @param varId     variable ID (e.g. Q1) of the operand
	 * @param operandId the index of the operand in the instruction
	 */
	public OperandMeta(TypeOfOperand type, List<Integer> mask, String varId, int operandId) {
		this.type = type;
		this.mask = mask;
		this.varId = varId;
		this.operandId = operandId;
	}

	public TypeOfOperand getType() {
		return type;
	}

	public List<Integer> getMask() {
		return mask;
	}

	public String getVarId() {
		return varId;
	}

	public JSONObject getJson() {
		JSONObject out = new JSONObject();
		out.put("type", type);
		out.put("mask", mask);
		out.put("var_id", varId);
		return out;
	}

	public String toString() {
		return "OperandMeta(varId: " + this.varId + ", type:" + this.type.toString() + ", operandId: " + this.operandId
				+ ", mask: " + this.mask.toString() + ")";
	}
}
