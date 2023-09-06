
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.querylanguage.lexer.ast;

import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableParseTreeNode;
import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableParseTreeNodeVisitor;
import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableResolvedContentNode;
import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableResolvedContentNodeVisitor;

public class MetaNode implements VisitableResolvedContentNode, VisitableParseTreeNode {

	private final String value;

	public MetaNode(String value) {
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}

	@Override
	public String getInstructionText() {
		return "META";
	}

	@Override
	public void accept(VisitableParseTreeNodeVisitor visitor) {
		visitor.visit(this);
	}

	@Override
	public void accept(VisitableResolvedContentNodeVisitor visitor) {
		visitor.visit(this);
	}
}
