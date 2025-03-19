
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

/**
 * Represents a variable that was a wildcard with the given var_id (e.g. Q1)
 * that has been found to have the concrete value of a given address (actually,
 * more accurately an sp index). It's typically found to have an address as its
 * value because it was specified as ":Q1" in the pattern.
 */
public class ConcreteOperandAddress extends ConcreteOperand {

	private final String varId; // variable name (e.g. Q1)
	private final long value; // address value of varId

	public ConcreteOperandAddress(String varId, long value) {
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
		return "" + this.value;
	}

	public long getValueLong() {
		return this.value;
	}

	@Override
	public String toString() {
		return "{" + this.varId + "=" + this.value + "}";
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
		ConcreteOperandAddress other = (ConcreteOperandAddress) obj;
		return Objects.equals(value, other.value) && Objects.equals(varId, other.varId);
	}
}
