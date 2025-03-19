
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

import org.mitre.pickledcanary.patterngenerator.output.utils.BitArray;

/**
 * Represents a variable that was a wildcard with the given var_id (e.g. Q1)
 * that has been found to have the concrete value of a scalar.
 */
public class ConcreteOperandScalar extends ConcreteOperand {

	private final String varId; // variable name (e.g. Q1)
	private final BitArray value; // scalar value of varId

	public ConcreteOperandScalar(String varId, BitArray value) {
		super(ConcreteOperand.TypeOfOperand.Scalar);
		this.varId = varId;
		this.value = value;
	}

	@Override
	public String getVarId() {
		return this.varId;
	}

	@Override
	public String getValue() {
		StringBuilder out = new StringBuilder("0x");
		for (Integer x : this.value.toIntList()) {
			String v = Integer.toHexString(x);
			if (v.length() == 1) {
				out.append('0');
			}
			out.append(v);
		}
		return out.toString();
	}

	@Override
	public String toString() {
		return "{" + this.varId + "=" + this.value.toString() + "}";
	}

	@Override
	public int hashCode() {
		return Objects.hash(value, varId);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		ConcreteOperandScalar other = (ConcreteOperandScalar) obj;
		return Objects.equals(value, other.value) && Objects.equals(varId, other.varId);
	}
}
