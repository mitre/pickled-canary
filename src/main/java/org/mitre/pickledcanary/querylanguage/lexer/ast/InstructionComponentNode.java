
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.querylanguage.lexer.ast;

public abstract class InstructionComponentNode implements ParseTreeNode {

	private final String text;

	public InstructionComponentNode(final String text) {
		this.text = text;
	}

	@Override
	public String toString() {
		return text;
	}
}
