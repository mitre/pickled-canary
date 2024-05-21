package org.mitre.pickledcanary.patterngenerator;

import java.util.*;

import org.antlr.v4.runtime.ParserRuleContext;
import org.json.JSONArray;
import org.json.JSONObject;

import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.asm.wild.WildSleighAssembler;
import ghidra.asm.wild.WildSleighAssemblerBuilder;
import ghidra.asm.wild.sem.WildAssemblyResolvedPatterns;
import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.patterngenerator.output.steps.AnyByteSequence;
import org.mitre.pickledcanary.patterngenerator.output.steps.Byte;
import org.mitre.pickledcanary.patterngenerator.output.steps.Jmp;
import org.mitre.pickledcanary.patterngenerator.output.steps.Label;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupStep;
import org.mitre.pickledcanary.patterngenerator.output.steps.MaskedByte;
import org.mitre.pickledcanary.patterngenerator.output.steps.Match;
import org.mitre.pickledcanary.patterngenerator.output.steps.NegativeLookahead;
import org.mitre.pickledcanary.patterngenerator.output.steps.OrMultiState;
import org.mitre.pickledcanary.patterngenerator.output.steps.Split;
import org.mitre.pickledcanary.patterngenerator.output.steps.SplitMulti;
import org.mitre.pickledcanary.patterngenerator.output.steps.Step;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;
import org.mitre.pickledcanary.patterngenerator.generated.pc_grammar;
import org.mitre.pickledcanary.patterngenerator.generated.pc_grammarBaseVisitor;
import org.mitre.pickledcanary.patterngenerator.output.utils.LookupStepBuilder;
import org.mitre.pickledcanary.search.Pattern;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.mitre.pickledcanary.util.PCAssemblerUtils;

public class PCVisitor extends pc_grammarBaseVisitor<Void> {

	private final Program currentProgram;
	private final Address currentAddress;
	private final WildSleighAssembler assembler;
	private final TaskMonitor monitor;

    // operand - binary representation tables

	private final List<OrMultiState> orStates;

	private final Deque<Integer> byteStack;

	private PatternContext currentContext;
	private final Deque<PatternContext> contextStack;


	private JSONObject metadata;

	/**
	 * Construct visitor to build Step output.
	 *
	 * @param currentProgram
	 * @param currentAddress
	 * @param monitor
	 */
	public PCVisitor(final Program currentProgram, final Address currentAddress,
			final TaskMonitor monitor) {
		this.currentProgram = currentProgram;
		this.currentAddress = currentAddress;
		this.monitor = monitor;
        SleighLanguage language = (SleighLanguage) currentProgram.getLanguage();
		WildSleighAssemblerBuilder builder = new WildSleighAssemblerBuilder(language);
		this.assembler = builder.getAssembler(new AssemblySelector(), currentProgram);

		this.orStates = new ArrayList<>();
		this.byteStack = new ArrayDeque<>();

		this.currentContext = new PatternContext();
		this.contextStack = new ArrayDeque<>();

		this.metadata = new JSONObject();
	}

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

		// If we have exactly two OR options, change from a SplitMulti to a Split
		if (middleSteps.size() == 1) {
			List<Integer> origDests =
				((SplitMulti) this.currentContext.steps().get(currentOrState.getStartStep())).getDests();

			Split newSplit = new Split(origDests.get(0));
			newSplit.setDest2(origDests.get(1));
			this.currentContext.steps().set(currentOrState.getStartStep(), newSplit);
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
		this.currentContext.steps.add(new Match());

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

		Collection<AssemblyParseResult> parses = assembler.parseLine(ctx.getText())
				.stream()
				.filter(p -> {
					if (PickledCanary.DEBUG && p.isError()) {
						System.err.println("Error in AssemblyParseResult: " + p);
					}
					return !p.isError();
				})
				.toList();
		if (parses.isEmpty()) {
			raiseInvalidInstructionException(ctx);
		}

		LookupStep lookupStep = this.makeLookupStepFromParseResults(parses);
		if (lookupStep == null) return null;
		if (lookupStep.isEmpty()) {
			raiseInvalidInstructionException(ctx);
		}

		this.currentContext.steps().add(lookupStep);

		return null;
	}

	private LookupStep makeLookupStepFromParseResults(Collection<AssemblyParseResult> parses) {
		LookupStepBuilder builder = new LookupStepBuilder(currentContext.tables);

		for (AssemblyParseResult p : parses) {
			if (PickledCanary.DEBUG) {
				System.err.println("parse = " + p);
			}
			AssemblyResolutionResults results = assembler.resolveTree(p, currentAddress);

			if (monitor.isCancelled()) {
				// Yield if user wants to cancel operation
				return null;
			}

			for (AssemblyResolution res : results) {
				if (res instanceof WildAssemblyResolvedPatterns pats) {
					builder.addAssemblyPattern(pats);
				}
			}
		}

		return builder.buildLookupStep();
	}
	
	public JSONObject getJSONObject(boolean withDebugInfo) {
		this.currentContext.canonicalize();
		JSONObject output = this.currentContext.getJson(this.metadata);

		if (withDebugInfo) {
			output.append("compile_info", this.getDebugJson());
		} else {
			ArrayList<String> compileInfo = new ArrayList<>();
			output.put("compile_info", compileInfo); // TODO <-- should this be a JSON object?
		}

		return output;
	}

	public Pattern getPattern() {
		this.currentContext.canonicalize();
		return this.currentContext.getPattern();
	}

	private static void raiseInvalidInstructionException(ParserRuleContext ctx) {
		String instructionText = ctx.getText();

		if (instructionText.chars().filter(ch -> ch == '`').count() % 2 != 0) {
			throw new QueryParseException(
					"This line doesn't have a balanced number of '`' characters and didn't assemble to any instruction", ctx);
		}
		else {
			throw new QueryParseException(
					"An assembly instruction in your pattern (" + instructionText +
							") did not return any output. Make sure your assembly instructions" +
							" are valid or that you are using a binary with the same architecture.", ctx);
		}
	}

	private JSONObject getDebugJson() {
		JSONObject compileInfo = new JSONObject();
		JSONObject sourceBinaryInfo = new JSONObject();
		sourceBinaryInfo.append("path", this.currentProgram.getExecutablePath());
		sourceBinaryInfo.append("md5", this.currentProgram.getExecutableMD5());
		sourceBinaryInfo.append("compiled_at_address", this.currentAddress);
		compileInfo.append("compiled_using_binary", sourceBinaryInfo);
		compileInfo.append("language_id", this.currentProgram.getLanguageID().getIdAsString());
		return compileInfo;
	}

	private record PatternContext(List<Step> steps, AllLookupTables tables) {
		PatternContext() {
			this(new ArrayList<>(), new AllLookupTables());
		}

		/**
		 * Replace temporary refs in the data structure with canonical id's.
		 */
		void canonicalize() {
			for (Step step : this.steps) {
				if (step instanceof LookupStep lookupStep) {
					lookupStep.resolveTableIds(this.tables);
				}
			}
		}

		Pattern getPattern() {
			return new Pattern(this.steps, this.tables.getPatternTables());
		}

		/**
		 * Get raw JSON (without) any debug or compile info
		 * @return the JSON for this context
		 */
		JSONObject getJson(JSONObject metadata) {
			JSONObject out = new JSONObject();

			JSONArray arr = new JSONArray();
			for (Step step : steps) {
				arr.put(step.getJson());
			}
			out.put("steps", arr);
			out.put("tables", tables.getJson());
			out.put("pattern_metadata", metadata);
			return out;
		}
	}
}
