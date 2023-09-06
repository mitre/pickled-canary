
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.querylanguage.lexer.ast;

import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableParseTreeNode;
import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableParseTreeNodeVisitor;

public class LineSeparatorNode implements VisitableParseTreeNode {

	@Override
	public void accept(VisitableParseTreeNodeVisitor visitor) {
		visitor.visit(this);
	}

	@Override
	public String getInstructionText() {
		return "\n";
	}

	@Override
	public String toString() {
		return "\n";
	}
}
