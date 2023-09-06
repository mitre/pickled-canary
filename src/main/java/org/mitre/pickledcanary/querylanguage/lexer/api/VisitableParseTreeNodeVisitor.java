
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.querylanguage.lexer.api;

import org.mitre.pickledcanary.querylanguage.lexer.ast.AnyBytesNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.ByteNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.InstructionNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.LabelNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.LineSeparatorNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.MaskedByteNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.MetaNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.NotEndNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.NotStartNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.OrEndNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.OrMiddleNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.OrStartNode;

public interface VisitableParseTreeNodeVisitor {

	void visit(AnyBytesNode anyBytesNode);

	void visit(InstructionNode instructionResolutionList);

	void visit(LineSeparatorNode instructionResolutionList);

	void visit(OrStartNode orStartNode);

	void visit(OrMiddleNode orMiddleNode);

	void visit(OrEndNode orEndNode);

	void visit(ByteNode byteNode);

	void visit(MaskedByteNode byteNode);

	void visit(NotStartNode notStartNode);

	void visit(NotEndNode notEndNode);

	void visit(MetaNode metaNode);

	void visit(LabelNode labelNode);
}
