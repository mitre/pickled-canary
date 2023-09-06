
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.querylanguage.lexer.api;

public interface VisitableResolvedContentNode {
	void accept(VisitableResolvedContentNodeVisitor visitor);
}
