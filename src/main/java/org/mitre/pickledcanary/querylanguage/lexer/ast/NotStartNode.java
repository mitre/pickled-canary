
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.querylanguage.lexer.ast;

import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableParseTreeNode;
import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableParseTreeNodeVisitor;
import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableResolvedContentNode;
import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableResolvedContentNodeVisitor;

public class NotStartNode implements VisitableResolvedContentNode, VisitableParseTreeNode {

	@Override
	public void accept(VisitableParseTreeNodeVisitor visitor) {
		visitor.visit(this);
	}

	@Override
	public void accept(VisitableResolvedContentNodeVisitor visitor) {
		visitor.visit(this);
	}

	@Override
	public String getInstructionText() {
		return "NOT";
	}
}
