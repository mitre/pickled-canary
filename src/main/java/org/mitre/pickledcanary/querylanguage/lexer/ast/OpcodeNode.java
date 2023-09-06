
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.querylanguage.lexer.ast;

public class OpcodeNode extends InstructionComponentNode {

	private final String opcode;

	public OpcodeNode(final String opcode) {
		super(opcode);
		this.opcode = opcode;
	}

	@Override
	public String getInstructionText() {
		return opcode;
	}
}
