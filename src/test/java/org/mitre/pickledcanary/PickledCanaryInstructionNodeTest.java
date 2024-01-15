
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary;

import org.junit.Assert;
import org.junit.Test;
import org.mitre.pickledcanary.querylanguage.lexer.Lexer;
import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableParseTreeNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.InstructionNode;
import org.mitre.pickledcanary.querylanguage.tokenizer.Tokenizer;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class PickledCanaryInstructionNodeTest extends AbstractGhidraHeadlessIntegrationTest {

	@Test
	public void generatePatternTestHelperInner() {
		final String simpleWildcardInstruction = "MOV EBP, `Q1/E.P/,$/4`";

		System.out.println("Starting test!");

		final var tokenizer = new Tokenizer(simpleWildcardInstruction);

		System.out.println("Created tokenizer!");

		final var tokens = tokenizer.tokenize(true);

		System.out.println("Tokenized!");

		final var lexer = new Lexer(tokens);

		System.out.println("Created lexer!");

		final var parseTree = lexer.lex();

		VisitableParseTreeNode node = (VisitableParseTreeNode) parseTree.stream().toArray()[0];

		Assert.assertEquals("MOV EBP, `Q1/E.P`", node.toString());

		Assert.assertTrue(node instanceof InstructionNode);

		InstructionNode inode = (InstructionNode) node;

		Assert.assertEquals("Q1", inode.getWildcardMap().get(9).getName());
		Assert.assertEquals("Q1", inode.getWildcardMap().get(10).getName());
		Assert.assertNull(inode.getWildcardMap().get(0));
		Assert.assertNull(inode.getWildcardMap().get(5));
		Assert.assertNull(inode.getWildcardMap().get(8));
	}
}
