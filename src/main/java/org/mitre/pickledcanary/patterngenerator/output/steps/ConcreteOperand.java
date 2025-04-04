
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

/**
 * Represents a variable that was a wildcard with the given var_id (e.g. Q1)
 * that has been found to have a concrete value (register name or scalar value).
 */
public abstract class ConcreteOperand {

	public enum TypeOfOperand {
		Field, Scalar
	}

	private final TypeOfOperand type;

	protected ConcreteOperand(TypeOfOperand x) {
		this.type = x;
	}

	public abstract String getVarId();

	public abstract String getValue();

	@Override
	public abstract String toString();

	public TypeOfOperand getType() {
		return this.type;
	}

	@Override
	public abstract boolean equals(Object o);

	@Override
	public abstract int hashCode();
}
