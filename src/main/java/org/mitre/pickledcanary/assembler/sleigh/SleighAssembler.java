/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.pickledcanary.assembler.sleigh;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;

import org.mitre.pickledcanary.assembler.*;
import org.mitre.pickledcanary.assembler.sleigh.parse.*;
import org.mitre.pickledcanary.assembler.sleigh.sem.*;
import org.mitre.pickledcanary.assembler.sleigh.symbol.AssemblyNumericSymbols;
import org.mitre.pickledcanary.assembler.sleigh.util.DbgTimer;
import org.mitre.pickledcanary.querylanguage.lexer.ast.InstructionNode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ChangeManager;
import ghidra.util.task.TaskMonitor;

/**
 * An {@link Assembler} for a {@link SleighLanguage}.
 * 
 * <p>
 * For documentation on how the SLEIGH assembler works, see {@link SleighAssemblerBuilder}. To use
 * the assembler, please use {@link Assemblers#getAssembler(Program)} or similar.
 */
public class SleighAssembler implements Assembler {
	protected static final DbgTimer dbg = DbgTimer.INACTIVE;

	protected class ListenerForSymbolsRefresh implements DomainObjectListener {
		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			if (ev.containsEvent(ChangeManager.DOCR_SYMBOL_ADDED) ||
				ev.containsEvent(ChangeManager.DOCR_SYMBOL_ADDRESS_CHANGED) ||
				ev.containsEvent(ChangeManager.DOCR_SYMBOL_REMOVED) ||
				ev.containsEvent(ChangeManager.DOCR_SYMBOL_RENAMED)) {
				synchronized (lock) {
					symbols = null;
				}
			}
		}
	}

	protected final Object lock = new Object();

	protected AssemblySelector selector;
	protected Program program;
	protected Listing listing;
	protected Memory memory;
	protected AssemblyParser parser;
	protected AssemblyDefaultContext defaultContext;
	protected AssemblyContextGraph ctxGraph;
	protected SleighLanguage lang;

	protected AssemblyNumericSymbols symbols;

	/**
	 * Construct a SleighAssembler.
	 * 
	 * @param selector a method of selecting one result from many
	 * @param program the program to bind to (must have same language as parser)
	 * @param parser the parser for the SLEIGH language
	 * @param defaultContext the default context for the language
	 * @param ctxGraph the context graph
	 */
	protected SleighAssembler(AssemblySelector selector, Program program, AssemblyParser parser,
			AssemblyDefaultContext defaultContext, AssemblyContextGraph ctxGraph) {
		this(selector, (SleighLanguage) program.getLanguage(), parser, defaultContext, ctxGraph);
		this.program = program;

		this.listing = program.getListing();
		this.memory = program.getMemory();
	}

	/**
	 * Construct a SleighAssembler.
	 * 
	 * <p>
	 * <b>NOTE:</b> This variant does not permit {@link #assemble(Address, String...)}.
	 * 
	 * @param selector a method of selecting one result from many
	 * @param lang the SLEIGH language (must be same as to create the parser)
	 * @param parser the parser for the SLEIGH language
	 * @param defaultContext the default context for the language
	 * @param ctxGraph the context graph
	 */
	protected SleighAssembler(AssemblySelector selector, SleighLanguage lang, AssemblyParser parser,
			AssemblyDefaultContext defaultContext, AssemblyContextGraph ctxGraph) {
		this.selector = selector;
		this.lang = lang;
		this.parser = parser;
		this.defaultContext = defaultContext;
		this.ctxGraph = ctxGraph;
	}

	@Override
	public Instruction patchProgram(AssemblyResolvedPatterns res, Address at)
			throws MemoryAccessException {
		if (!res.getInstruction().isFullMask()) {
			throw new AssemblySelectionError("Selected instruction must have a full mask.");
		}
		return patchProgram(res.getInstruction().getVals(), at).next();
	}

	@Override
	public InstructionIterator patchProgram(byte[] insbytes, Address at)
			throws MemoryAccessException {
		if (insbytes.length == 0) {
			return listing.getInstructions(new AddressSet(), true);
		}
		Address end = at.add(insbytes.length - 1);
		listing.clearCodeUnits(at, end, false);
		memory.setBytes(at, insbytes);
		AddressSet set = new AddressSet(at, end);

		// Creating this at construction causes it to assess memory flags too early.
		Disassembler dis = Disassembler.getDisassembler(program, TaskMonitor.DUMMY,
			DisassemblerMessageListener.IGNORE);
		dis.disassemble(at, set);
		return listing.getInstructions(set, true);
	}

	@Override
	public InstructionIterator assemble(Address at, String... assembly)
			throws AssemblySyntaxException, AssemblySemanticException, MemoryAccessException,
			AddressOverflowException {
		Address start = at;
		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		for (String part : assembly) {
			for (String line : part.split("\n")) {
				RegisterValue rv = program.getProgramContext().getDisassemblyContext(at);
				dbg.println(rv);
				AssemblyPatternBlock ctx = AssemblyPatternBlock.fromRegisterValue(rv);
				ctx = ctx.fillMask();
				byte[] insbytes = assembleLine(at, line, ctx);
				if (insbytes == null) {
					return null;
				}
				try {
					buf.write(insbytes);
				}
				catch (IOException e) {
					throw new AssertionError(e);
				}
				at = at.addNoWrap(insbytes.length);
			}
		}
		return patchProgram(buf.toByteArray(), start);
	}

	@Override
	public byte[] assembleLine(Address at, String line)
			throws AssemblySyntaxException, AssemblySemanticException {
		AssemblyPatternBlock ctx = defaultContext.getDefaultAt(at);
		ctx = ctx.fillMask();
		return assembleLine(at, line, ctx);
	}

	@Override
	public Collection<AssemblyParseResult> parseLine(String line) {
		return parser.parse(line, getNumericSymbols());
	}
	
	@Override
	public Collection<AssemblyParseResult> parseLine(InstructionNode line, TaskMonitor monitor) {
		return parser.parse(line, getNumericSymbols(), monitor);
	}


	@Override
	public AssemblyResolutionResults resolveTree(AssemblyParseResult parse, Address at) {
		AssemblyPatternBlock ctx = getContextAt(at);
		ctx = ctx.fillMask();
		return resolveTree(parse, at, ctx);
	}

	@Override
	public AssemblyResolutionResults resolveTree(AssemblyParseResult parse, Address at,
			AssemblyPatternBlock ctx) {
		if (parse.isError()) {
			AssemblyResolutionResults results = new AssemblyResolutionResults();
			AssemblyParseErrorResult err = (AssemblyParseErrorResult) parse;
			results.add(AssemblyResolution.error(err.describeError(), "Parsing"));
			return results;
		}

		AssemblyParseAcceptResult acc = (AssemblyParseAcceptResult) parse;
		AssemblyTreeResolver tr =
			new AssemblyTreeResolver(lang, at, acc.getTree(), ctx, ctxGraph);
		return tr.resolve();
	}

	@Override
	public AssemblyResolutionResults resolveLine(Address at, String line)
			throws AssemblySyntaxException {
		return resolveLine(at, line, getContextAt(at).fillMask());
	}

	@Override
	public AssemblyResolutionResults resolveLine(Address at, String line, AssemblyPatternBlock ctx)
			throws AssemblySyntaxException {

		if (!ctx.isFullMask()) {
			throw new AssemblyError(
				"Context must be fully-specified (full length, no shift, no unknowns)");
		}
		if (lang.getContextBaseRegister() != Register.NO_CONTEXT &&
			ctx.length() < lang.getContextBaseRegister().getMinimumByteSize()) {
			throw new AssemblyError(
				"Context must be fully-specified (full length, no shift, no unknowns)");
		}
		Collection<AssemblyParseResult> parse = parseLine(line);
		parse = selector.filterParse(parse);
		if (!parse.iterator().hasNext()) { // Iterator.isEmpty()???
			throw new AssemblySelectionError(
				"Must select at least one parse result. Report errors via AssemblySyntaxError");
		}
		AssemblyResolutionResults results = new AssemblyResolutionResults();
		for (AssemblyParseResult p : parse) {
			results.absorb(resolveTree(p, at, ctx));
		}
		return results;
	}
	
	@Override
	public AssemblyResolutionResults resolveLine(Address at, InstructionNode line,
			AssemblyPatternBlock ctx, TaskMonitor monitor) throws AssemblySyntaxException {

		if (!ctx.isFullMask()) {
			throw new AssemblyError(
				"Context must be fully-specified (full length, no shift, no unknowns)");
		}
		if (lang.getContextBaseRegister() != null &&
			ctx.length() < lang.getContextBaseRegister().getMinimumByteSize()) {
			throw new AssemblyError(
				"Context must be fully-specified (full length, no shift, no unknowns)");
		}
		Collection<AssemblyParseResult> parse = parseLine(line, monitor);
		if (monitor.isCancelled()) {
			return new AssemblyResolutionResults();
		}
		parse = selector.filterParse(parse);
		if (!parse.iterator().hasNext()) { // Iterator.isEmpty()???
			throw new AssemblySelectionError(
				"Must select at least one parse result. Report errors via AssemblySyntaxError");
		}
		AssemblyResolutionResults results = new AssemblyResolutionResults();
		for (AssemblyParseResult p : parse) {
			if (monitor.isCancelled()) {
				return new AssemblyResolutionResults();
			}
			results.absorb(resolveTree(p, at, ctx));
		}
		return results;
	}

	@Override
	public byte[] assembleLine(Address at, String line, AssemblyPatternBlock ctx)
			throws AssemblySemanticException, AssemblySyntaxException {
		AssemblyResolutionResults results = resolveLine(at, line, ctx);
		AssemblyResolvedPatterns res = selector.select(results, ctx);
		if (res == null) {
			throw new AssemblySelectionError(
				"Must select exactly one instruction. Report errors via AssemblySemanticError");
		}
		if (!res.getInstruction().isFullMask()) {
			throw new AssemblySelectionError("Selected instruction must have a full mask.");
		}
		if (res.getContext().combine(ctx) == null) {
			throw new AssemblySelectionError("Selected instruction must have compatible context");
		}
		return res.getInstruction().getVals();
	}

	/**
	 * A convenience to obtain assembly symbols
	 * 
	 * @return the map
	 */
	protected AssemblyNumericSymbols getNumericSymbols() {
		synchronized (lock) {
			if (symbols != null) {
				return symbols;
			}
			if (program == null) {
				symbols = AssemblyNumericSymbols.fromLanguage(lang);
			}
			else {
				symbols = AssemblyNumericSymbols.fromProgram(program);
			}
			return symbols;
		}
	}

	@Override
	public AssemblyPatternBlock getContextAt(Address addr) {
		if (program != null) {
			RegisterValue rv = program.getProgramContext().getDisassemblyContext(addr);
			return AssemblyPatternBlock.fromRegisterValue(rv);
		}
		return defaultContext.getDefaultAt(addr);
	}
}
