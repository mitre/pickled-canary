
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.querylanguage.lexer.ast;

public interface ParseTreeNode {

	/**
	 * Get the text that represents the instruction that the user entered.
	 * 
	 * @return text representing the instruction that user entered
	 */
	String getInstructionText();

}
