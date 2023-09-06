
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.frontend;

import org.mitre.pickledcanary.patterngenerator.output.Format;
import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableParseTreeNodeVisitor;
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

public class NodeVisitor implements VisitableParseTreeNodeVisitor {

	private final Format format;

	NodeVisitor(final Format format) {
		// TODO: remove?
		this.format = format;
	}

	@Override
	public void visit(final AnyBytesNode anyBytesNode) {
		format.addNextInstruction(anyBytesNode);
	}

	@Override
	public void visit(final InstructionNode instructionNode) {
		format.addNextInstruction(instructionNode);
	}

	@Override
	public void visit(final LineSeparatorNode parseTreeNode) {
		/* no-op */
	}

	@Override
	public void visit(final OrStartNode orStartNode) {
		format.addNextInstruction(orStartNode);
	}

	@Override
	public void visit(final OrMiddleNode orMiddleNode) {
		format.addNextInstruction(orMiddleNode);
	}

	@Override
	public void visit(final OrEndNode orEndNode) {
		format.addNextInstruction(orEndNode);
	}

	@Override
	public void visit(final ByteNode byteNode) {
		format.addNextInstruction(byteNode);
	}

	@Override
	public void visit(final MaskedByteNode maskedByteNode) {
		format.addNextInstruction(maskedByteNode);
	}

	@Override
	public void visit(final NotStartNode notStartNode) {
		format.addNextInstruction(notStartNode);
	}

	@Override
	public void visit(final NotEndNode notStartNode) {
		format.addNextInstruction(notStartNode);
	}

	@Override
	public void visit(MetaNode metaNode) {
		format.addNextInstruction(metaNode);
	}

	@Override
	public void visit(LabelNode labelNode) {
		format.addNextInstruction(labelNode);
	}
}
