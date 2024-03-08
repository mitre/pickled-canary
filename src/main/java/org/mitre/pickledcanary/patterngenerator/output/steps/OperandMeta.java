
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.List;

import org.json.JSONObject;

/**
 * Represents operand choices for wildcards in the output json.
 */
public abstract class OperandMeta implements Comparable<OperandMeta>{

	public enum TypeOfOperand {
		Field, Scalar
	}

	protected final TypeOfOperand type;
	protected final List<Integer> mask;
	protected final String varId;

	/**
	 * OperandMeta
	 * 
	 * @param type      TypeOfOperand
	 * @param mask      mask of an operand
	 * @param varId     variable ID (e.g. Q1) of the operand
	 */
	public OperandMeta(TypeOfOperand type, List<Integer> mask, String varId) {
		this.type = type;
		this.mask = mask;
		this.varId = varId;
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
		return "OperandMeta(varId: " + this.varId + ", type:" + this.type.toString() + ", mask: " +
			this.mask.toString() + ")";
	}
	
	public int compareTo(OperandMeta other) {
		var out = this.varId.compareTo(other.varId);
		if (out != 0) {
			return out;
		}
		
		for (var i = 0; i < Math.min(this.mask.size(), other.mask.size()); i++) {
			out = this.mask.get(i).compareTo(other.mask.get(i));
			if (out != 0) {
				return out;
			}
		}
		
		return Integer.valueOf(this.mask.size()).compareTo(Integer.valueOf(other.mask.size()));
	}
}
