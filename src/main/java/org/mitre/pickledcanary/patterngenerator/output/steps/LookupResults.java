
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.List;

public class LookupResults {

	private final int size;
	private final List<ConcreteOperand> operands;

	public LookupResults(int size, List<ConcreteOperand> operands) {
		this.size = size;
		this.operands = operands;
	}

	public int getMatchSize() {
		return this.size;
	}

	public List<ConcreteOperand> getOperands() {
		return this.operands;
	}

	public String toString() {
		return "LookupResults(size:" + this.size + ", operands:" + this.operands.toString() + ")";
	}

}
