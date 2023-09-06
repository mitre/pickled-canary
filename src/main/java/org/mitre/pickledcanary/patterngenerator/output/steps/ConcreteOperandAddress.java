
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

	final private String var_id;
	final private Long value;

	public ConcreteOperandAddress(String var_id, Long x) {
		super(ConcreteOperand.TypeOfOperand.Scalar);
		this.var_id = var_id;
		this.value = x;
	}

	@Override
	public String getVarId() {
		return this.var_id;
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
		return "{" + this.var_id + "=" + this.value + "}";
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
		return this.var_id.equals(that.getVarId());
	}
}
