// Copyright (C) 2025 The MITRE Corporation All Rights Reserved
package org.mitre.pickledcanary.patterngenerator;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

import org.json.JSONObject;
import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.patterngenerator.PCVisitor.PatternContext;
import org.mitre.pickledcanary.patterngenerator.generated.pc_grammar;
import org.mitre.pickledcanary.patterngenerator.generated.pc_grammar.ProgContext;
import org.mitre.pickledcanary.patterngenerator.generated.pc_grammarBaseVisitor;
import org.mitre.pickledcanary.patterngenerator.output.steps.AnyByteSequence;
import org.mitre.pickledcanary.patterngenerator.output.steps.Byte;
import org.mitre.pickledcanary.patterngenerator.output.steps.Context;
import org.mitre.pickledcanary.patterngenerator.output.steps.Jmp;
import org.mitre.pickledcanary.patterngenerator.output.steps.Label;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupStep;
import org.mitre.pickledcanary.patterngenerator.output.steps.MaskedByte;
import org.mitre.pickledcanary.patterngenerator.output.steps.Match;
import org.mitre.pickledcanary.patterngenerator.output.steps.NegativeLookahead;
import org.mitre.pickledcanary.patterngenerator.output.steps.OrMultiState;
import org.mitre.pickledcanary.patterngenerator.output.steps.SplitMulti;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;

/**
 * This class contains the first step to creating the generated pattern. This step converts ANTLR
 * tokens into initial steps of the generated pattern. Assembly instruction tokens are ignored and
 * processed in the second step.
 */
public class Visitor extends pc_grammarBaseVisitor<Void> {
	private final Program currentProgram;
	private final List<OrMultiState> orStates;
	private final Deque<Integer> byteStack;
	private final Deque<PatternContext> contextStack;
	private PatternContext currentContext; // contains output of first visitor
	private JSONObject metadata;
	
	/**
	 * Individual key-value pairs within a single "CONTEXT" block
	 */
	private final HashMap<String, RegisterValue> contextEntries;
	
	/**
	 * Local cache so we're not constantly querying to get this list
	 */
	private List<Register> validContextRegisters = null;
	
	Visitor(final Program currentProgram) {
		this.currentProgram = currentProgram;
		this.orStates = new ArrayList<>();
		this.byteStack = new ArrayDeque<>();
		this.currentContext = new PatternContext();
		this.contextStack = new ArrayDeque<>();
		this.metadata = new JSONObject();
		this.contextEntries = new HashMap<>();
	}
	
	void reset() {
		this.orStates.clear();
		this.byteStack.clear();
		this.currentContext = new PatternContext();
		this.contextStack.clear();
		this.metadata = new JSONObject();
		this.contextEntries.clear();
	}
	
	public PatternContext getContext(ProgContext progContext) {
		this.visit(progContext);
		return this.currentContext;
	}
	
	public JSONObject getMetadata() {
		return this.metadata;
	}

	// region Visit methods
	@Override
	public Void visitAny_bytes(pc_grammar.Any_bytesContext ctx) {

		Integer min = Integer.decode(ctx.getChild(1).getText());
		Integer max = Integer.decode(ctx.getChild(3).getText());
		Integer step = 1;

		if (ctx.children.size() > 6) {
			step = Integer.decode(ctx.getChild(5).getText());
		}

		var note = String.format(
				"AnyBytesNode Start: %d End: %d Interval: %d From: Token from line #%d: Token type: PICKLED_CANARY_COMMAND data: `%s`",
				min, max, step, ctx.start.getLine(), ctx.getText());

		this.currentContext.steps().add(new AnyByteSequence(min, max, step, note));

		return null;
	}

	@Override
	public Void visitByte_match(pc_grammar.Byte_matchContext ctx) {
		visitChildren(ctx);
		this.currentContext.steps().add(new Byte(this.byteStack.pop()));
		return null;
	}

	@Override
	public Void visitByte_string(pc_grammar.Byte_stringContext ctx) {

		var stringData = ctx.getText().strip();
		// Remove starting and ending '"' and translate escapes
		stringData = stringData.substring(1, stringData.length() - 1).translateEscapes();

		// Add a "Byte" for each character
		for (int x : stringData.toCharArray()) {
			this.currentContext.steps().add(new Byte(x));
		}

		return null;
	}

	@Override
	public Void visitMasked_byte(pc_grammar.Masked_byteContext ctx) {
		visitChildren(ctx);
		var value = this.byteStack.pop();
		var mask = this.byteStack.pop();
		this.currentContext.steps().add(new MaskedByte(mask, value));
		return null;
	}

	@Override
	public Void visitByte(pc_grammar.ByteContext ctx) {
		this.byteStack.push(Integer.decode(ctx.getText()));
		return null;
	}

	@Override
	public Void visitLabel(pc_grammar.LabelContext ctx) {
		var label = ctx.getText().strip();
		label = label.substring(0, label.length() - 1);
		this.currentContext.steps().add(new Label(label));
		return null;
	}

	@Override
	public Void visitMeta(pc_grammar.MetaContext ctx) {
		String meta = ctx.getText();
		// Remove `META` at the start
		meta = meta.replaceFirst("^ *`META`[\r\n]+", "");
		// Remove "`META_END`" at the end
		meta = meta.substring(0, meta.length() - 10);
		// Remove any comments
		meta = meta.replaceAll("[\n\r]+ *;[^\n\r]*", "");

		// Check if our existing metadata is equal to an empty JSONObject
		if (this.metadata.toString().equals(new JSONObject().toString())) {
			this.metadata = new JSONObject(meta);
		} else {
			throw new QueryParseException("Can not have more than one META section!", ctx);
		}
		return null;
	}

	@Override
	public Void visitStart_or(pc_grammar.Start_orContext ctx) {
		// Add a new "split" step for this OR block.
		this.currentContext.steps().add(new SplitMulti(this.currentContext.steps().size() + 1));

		// Add a new OrState and reference the index of the split node for this Or block
		this.orStates.add(new OrMultiState(this.currentContext.steps().size() - 1));
		return null;
	}

	@Override
	public Void visitMiddle_or(pc_grammar.Middle_orContext ctx) {
		// Add a new "jmp" step to (eventually) go to after the second "or" option.
		this.currentContext.steps().add(new Jmp(this.currentContext.steps().size() + 1));

		OrMultiState currentOrState = this.orStates.get(this.orStates.size() - 1);
		currentOrState.addMiddleStep(this.currentContext.steps().size() - 1);

		// Update the split to have its next dest point to here after the jmp ending
		// the first option
		SplitMulti s = (SplitMulti) this.currentContext.steps().get(currentOrState.getStartStep());
		s.addDest(this.currentContext.steps().size());
		return null;
	}

	@Override
	public Void visitEnd_or(pc_grammar.End_orContext ctx) {
		// Pop the current orState off the end (we're done with it)
		OrMultiState currentOrState = this.orStates.remove(this.orStates.size() - 1);

		// Update the jmp after each "or" option to jump to here (after the final
		// "or")
		List<Integer> middleSteps = currentOrState.getMiddleSteps();
		for (Integer jmp_idx : middleSteps) {
			Jmp j = (Jmp) this.currentContext.steps().get(jmp_idx);
			j.setDest(this.currentContext.steps().size());
		}
		return null;
	}

	@Override
	public Void visitStart_negative_lookahead(pc_grammar.Start_negative_lookaheadContext ctx) {
		// When we get into a "not" block, we'll essentially start to create a new
		// pattern (for the contents of the "not" block). We do this here by saving off
		// our current "steps" and "tables" and creating new ones that our next nodes
		// (until the end of the not block) will populate. When we get to the end of the
		// "not" block, we'll package up the then-current steps and tables into a
		// pattern (the new ones we're creating here), restore the steps and tables
		// saved here, and add the "NegativeLookahead" step containing the
		// just-generated pattern.
		this.contextStack.push(this.currentContext);
		this.currentContext = new PatternContext();
		return null;
	}

	@Override
	public Void visitEnd_negative_lookahead(pc_grammar.End_negative_lookaheadContext ctx) {
		// The final step of the not block should be a Match, so add it here.
		this.currentContext.getSteps().add(new Match());

		// Generate the JSON for the inner-pattern (that will go within the
		// NegativeLookahead)
		this.currentContext.canonicalize();
		JSONObject notPattern = this.currentContext.getJson(this.metadata);

		// Restore our "outer"/"main" steps and tables (which were saved at the
		// NotStartNode)
		this.currentContext = this.contextStack.pop();

		// Add the NegativeLookahead step (including its inner-pattern) to our main set
		// of steps
		this.currentContext.steps().add(new NegativeLookahead(notPattern));
		return null;
	}

	@Override
	public Void visitInstruction(pc_grammar.InstructionContext ctx) {
		if (PickledCanary.DEBUG) {
			System.out.println("CURRENTLY PROCESSING: " + ctx.getText());
		}

		LookupStep lookupStep = new LookupStep(ctx.getText(), ctx.start.getLine(),
				ctx.start.getCharPositionInLine());

		this.currentContext.steps().add(lookupStep);

		return null;
	}
	
	@Override
	public Void visitContext_entry(pc_grammar.Context_entryContext ctx) {

		String[] parts = ctx.getText().split("=");
		String name = parts[0].strip();
		String valueString = parts[1].strip();
		RegisterValue contextVar;

		// Check name is valid
		if (this.contextEntries.containsKey(name)) {
			throw new QueryParseException(
				"Cannot specify context value more than once! '" + name + "' was duplicated.", ctx);
		}

		if (this.validContextRegisters == null) {
			this.validContextRegisters = currentProgram.getProgramContext().getContextRegisters();
		}
		Optional<Register> match = this.validContextRegisters.stream()
				.filter(reg -> reg.getName().equals(name))
				.findFirst();

		if (match.isEmpty()) {
			throw new QueryParseException("Invalid context variable '" + name + "' for language!",
				ctx);

		}

		// Parse value for name

		BigInteger value = null;

		// If we have a quoted string, we're dealing with the
		// NumericUtilities#convertHexStringToMaskedValue(AtomicLong, AtomicLong, String, int, int,
		// String) format
		if (valueString.startsWith("\"") || valueString.startsWith("'")) {
			if (!valueString.endsWith(valueString.substring(0, 1))) {
				throw new QueryParseException("Expected quoted string to end with a matching quote",
					ctx);
			}

			// Remove first and last characters (the quote characters we just found above)
			String valueStringInner = valueString.substring(1, valueString.length() - 1);

			// Parse the given string to an AssemblyPatternBlock and then convert that a
			// RegisterValue
			// TODO: Do we need to be more sophisticated in our conversion here, especially when the
			// input string might start with 1 and be seen as negative in the BigIntegers
			AssemblyPatternBlock a = AssemblyPatternBlock.fromString(valueStringInner);

			value = new BigInteger(a.getValsAll());
			BigInteger mask = new BigInteger(a.getMaskAll());
			contextVar = new RegisterValue(match.get(), value, mask);

		}
		else {
			// Else try simpler radix based formats (with no unknown bits)
			try {
				if (valueString.length() > 2) {
					String valuePrefix = valueString.substring(0, 2);
					if (valuePrefix.equals("0x")) {
						value = new BigInteger(valueString.substring(2), 16);
					}
					else if (valuePrefix.equals("0b")) {
						value = new BigInteger(valueString.substring(2), 2);
					}
				}
				if (value == null) {
					value = new BigInteger(valueString);
				}
			}
			catch (NumberFormatException e) {
				throw new QueryParseException(
					"Unable to parse context value: '" + valueString +
						" '. Is it properly prefixed with '0x' for hex, '0b' for binary, or no prefix for base 10?",
					ctx);
			}

			contextVar = new RegisterValue(match.get(), value);
		}
		
		System.err.println("Going to set this context variable: " + contextVar);
		this.contextEntries.put(name, contextVar);

		return null;
	}

	@Override
	public Void visitContext(pc_grammar.ContextContext ctx) {
		visitChildren(ctx);
		// Transient context override step
		Context contextStep = new Context();
		
		for (RegisterValue contextVar: contextEntries.values()) {
			contextStep.addContextVar(contextVar);
		}
		
		// Reset entries so we're ready for the next context block
		contextEntries.clear();

		this.currentContext.steps().add(contextStep);
 
		return null;
	}
	// end region
}
