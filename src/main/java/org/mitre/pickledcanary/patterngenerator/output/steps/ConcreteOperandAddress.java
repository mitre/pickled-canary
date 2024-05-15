
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

/**
 * Represents a variable that was a wildcard with the given var_id (e.g. Q1)
 * that has been found to have the concrete value of a given address (actually,
 * more accurately an sp index). It's typically found to have an address as its
 * value because it was specified as ":Q1" in the pattern.
 *
 */
public class ConcreteOperandAddress extends ConcreteOperand {

	private final String varId;
	private final Long value;

	public ConcreteOperandAddress(String varId, Long x) {
		super(ConcreteOperand.TypeOfOperand.Scalar);
		this.varId = varId;
		this.value = x;
	}

	@Override
	public String getVarId() {
		return this.varId;
	}

	@Override
	public String getValue() {
		return "" + this.value;
	}

	public Long getValueLong() {
		return this.value;
	}

	@Override
	public String toString() {
		return "{" + this.varId + "=" + this.value + "}";
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof ConcreteOperandAddress)) {
			return false;
		}
		ConcreteOperandAddress that = (ConcreteOperandAddress) o;
		if (Objects.equals(this.value, that.getValueLong())) {
			return false;
		}
		return this.varId.equals(that.getVarId());
	}
}
