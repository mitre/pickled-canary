
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.List;
import java.util.Objects;

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
	protected OperandMeta(TypeOfOperand type, List<Integer> mask, String varId) {
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

	@Override
	public String toString() {
		return "OperandMeta(varId: " + this.varId + ", type:" + this.type.toString() + ", mask: " +
			this.mask.toString() + ")";
	}

	@Override
	public int compareTo(OperandMeta other) {

		if (this.type != other.type) {
			if (this.type == TypeOfOperand.Field) {
				return -1;
			}
			return 1;
		}

		var out = this.varId.compareTo(other.varId);
		if (out != 0) {
			return out;
		}

		out = Integer.compare(this.mask.size(), other.mask.size());
		if (out != 0) {
			return out;
		}

		for (var i = 0; i < Math.min(this.mask.size(), other.mask.size()); i++) {
			out = this.mask.get(i).compareTo(other.mask.get(i));
			if (out != 0) {
				return out;
			}
		}

		return 0;
	}

	@Override
	public int hashCode() {
		return Objects.hash(mask, type, varId);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		OperandMeta other = (OperandMeta) obj;
		return Objects.equals(mask, other.mask) && type == other.type &&
			Objects.equals(varId, other.varId);
	}
}
