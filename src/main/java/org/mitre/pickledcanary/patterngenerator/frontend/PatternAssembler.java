
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.frontend;

import java.util.function.Consumer;

import org.mitre.pickledcanary.patterngenerator.output.steps.StepFormat;
import org.mitre.pickledcanary.querylanguage.lexer.ParseTree;
import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableParseTreeNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.ParseTreeNode;
import org.mitre.pickledcanary.search.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class PatternAssembler {

	public static enum AssembleType {
		JSON, PATTERN
	}

	private StepFormat assembleCommon(final Program program, final ParseTree parseTree, final Address address,
			final TaskMonitor monitor) {
		final var format = new StepFormat(program, address, monitor);

		final var visitor = new NodeVisitor(format);
		final var consume = (Consumer<ParseTreeNode>) (node) -> {
			System.out.println("compiling " + node.getInstructionText() + " : " + node.getClass());
			monitor.setMessage("Compiling " + node.getInstructionText());
			((VisitableParseTreeNode) node).accept(visitor);
		};

		parseTree.stream().forEachOrdered(consume);
		return format;
	}

	public Object assemble(AssembleType type, final Program program, final ParseTree parseTree, final Address address,
			final Language language, final TaskMonitor monitor, Boolean removeDebugInfo) {
		if (type == AssembleType.JSON) {
			return assemble(program, parseTree, address, monitor, removeDebugInfo);
		} else if (type == AssembleType.PATTERN) {
			return assemblePattern(program, parseTree, address, monitor);
		} else {
			throw new UnsupportedOperationException("AssembleType not fully implemented. Did you add a new one?");
		}
	}

	public String assemble(final Program program, final ParseTree parseTree, final Address address,
			final TaskMonitor monitor, Boolean removeDebugInfo) {

		final var format = assembleCommon(program, parseTree, address, monitor);
		if (removeDebugInfo) {
			return format.getBinaryWithoutDebug();
		}
		return format.getBinaryRepresentation();

	}

	public Pattern assemblePattern(final Program program, final ParseTree parseTree, final Address address,
			final TaskMonitor monitor) {

		final var format = assembleCommon(program, parseTree, address, monitor);

		return format.getPattern();
	}
}
