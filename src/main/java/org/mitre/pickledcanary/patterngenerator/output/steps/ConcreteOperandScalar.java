
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import org.mitre.pickledcanary.patterngenerator.output.utils.BitArray;

/**
 * Represents a variable that was a wildcard with the given var_id (e.g. Q1)
 * that has been found to have the concrete value of a scalar
 */
public class ConcreteOperandScalar extends ConcreteOperand {

	final private String var_id;
	final private BitArray value;

	public ConcreteOperandScalar(String var_id, BitArray value) {
		super(ConcreteOperand.TypeOfOperand.Scalar);
		this.var_id = var_id;
		this.value = value;
	}

	@Override
	public String getVarId() {
		return this.var_id;
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

	public BitArray getValuePCBitArray() {
		return this.value;
	}

	@Override
	public String toString() {
		return "{" + this.var_id + "=" + this.value.toString() + "}";
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof ConcreteOperandScalar)) {
			return false;
		}
		ConcreteOperandScalar that = (ConcreteOperandScalar) o;
		if (!this.value.equals(that.getValuePCBitArray())) {
			return false;
		}
		return this.var_id.equals(that.getVarId());
	}
}
