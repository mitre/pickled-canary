
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

/**
 * Represents a variable that was a wildcard with the given var_id (e.g. Q1)
 * that has been found to have the concrete register name name
 *
 */
public class ConcreteOperandField extends ConcreteOperand {

	final private String var_id;
	final private String name;

	public ConcreteOperandField(String var_id, String name) {
		super(ConcreteOperand.TypeOfOperand.Field);
		this.var_id = var_id;
		this.name = name;
	}

	@Override
	public String getVarId() {
		return this.var_id;
	}

	@Override
	public String getValue() {
		return this.name;
	}

	@Override
	public String toString() {
		return "{" + this.var_id + "=" + this.name + "}";
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
		return this.var_id.equals(that.getVarId());
	}

}
