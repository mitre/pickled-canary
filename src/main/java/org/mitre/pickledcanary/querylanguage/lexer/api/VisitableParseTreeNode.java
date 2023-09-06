
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.querylanguage.lexer.api;

import org.mitre.pickledcanary.querylanguage.lexer.ast.ParseTreeNode;

public interface VisitableParseTreeNode extends ParseTreeNode {
	void accept(VisitableParseTreeNodeVisitor visitor);
}
