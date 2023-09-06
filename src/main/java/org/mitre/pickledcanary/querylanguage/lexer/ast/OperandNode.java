
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.querylanguage.lexer.ast;

public class OperandNode extends InstructionComponentNode {

	private final String operand;

	public OperandNode(final String operand) {
		super(operand);
		this.operand = operand;
	}

	@Override
	public String getInstructionText() {
		return operand;
	}
}
