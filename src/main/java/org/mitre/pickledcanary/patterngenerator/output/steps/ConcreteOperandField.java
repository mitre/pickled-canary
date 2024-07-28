
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

/**
 * Represents a variable that was a wildcard with the given var_id (e.g. Q1)
 * that has been found to have the concrete register name name
 *
 */
public class ConcreteOperandField extends ConcreteOperand {

	private final String varId;
	private final String name;

	public ConcreteOperandField(String varId, String name) {
		super(ConcreteOperand.TypeOfOperand.Field);
		this.varId = varId;
		this.name = name;
	}

	@Override
	public String getVarId() {
		return this.varId;
	}

	@Override
	public String getValue() {
		return this.name;
	}

	@Override
	public String toString() {
		return "{" + this.varId + "=" + this.name + "}";
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof ConcreteOperandField)) {
			return false;
		}
		ConcreteOperandField that = (ConcreteOperandField) o;
		if (!this.name.equals(that.getValue())) {
			return false;
		}
		return this.varId.equals(that.getVarId());
	}

}
