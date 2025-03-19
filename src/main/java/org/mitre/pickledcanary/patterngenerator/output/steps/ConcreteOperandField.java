
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

/**
 * Represents a variable that was a wildcard with the given var_id (e.g. Q1)
 * that has been found to have the concrete register name.
 */
public class ConcreteOperandField extends ConcreteOperand {

	private final String varId; // variable name (e.g. Q1)
	private final String name; // register name value of varId

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
	public int hashCode() {
		return Objects.hash(name, varId);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		ConcreteOperandField other = (ConcreteOperandField) obj;
		return Objects.equals(name, other.name) && Objects.equals(varId, other.varId);
	}
}
