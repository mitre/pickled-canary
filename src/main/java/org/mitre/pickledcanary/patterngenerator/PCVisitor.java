package org.mitre.pickledcanary.patterngenerator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Stack;

import org.json.JSONArray;
import org.json.JSONObject;

import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.asm.wild.WildOperandInfo;
import ghidra.asm.wild.WildSleighAssembler;
import ghidra.asm.wild.WildSleighAssemblerBuilder;
import ghidra.asm.wild.sem.WildAssemblyResolvedPatterns;
import org.mitre.pickledcanary.patterngenerator.output.steps.AnyByteSequence;
import org.mitre.pickledcanary.patterngenerator.output.steps.Byte;
import org.mitre.pickledcanary.patterngenerator.output.steps.Data;
import org.mitre.pickledcanary.patterngenerator.output.steps.FieldOperandMeta;
import org.mitre.pickledcanary.patterngenerator.output.steps.InstructionEncoding;
import org.mitre.pickledcanary.patterngenerator.output.steps.Jmp;
import org.mitre.pickledcanary.patterngenerator.output.steps.Label;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupData;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupStep;
import org.mitre.pickledcanary.patterngenerator.output.steps.MaskedByte;
import org.mitre.pickledcanary.patterngenerator.output.steps.Match;
import org.mitre.pickledcanary.patterngenerator.output.steps.NegativeLookahead;
import org.mitre.pickledcanary.patterngenerator.output.steps.OperandMeta;
import org.mitre.pickledcanary.patterngenerator.output.steps.OrMultiState;
import org.mitre.pickledcanary.patterngenerator.output.steps.ScalarOperandMeta;
import org.mitre.pickledcanary.patterngenerator.output.steps.Split;
import org.mitre.pickledcanary.patterngenerator.output.steps.SplitMulti;
import org.mitre.pickledcanary.patterngenerator.output.steps.Step;
import org.mitre.pickledcanary.patterngenerator.output.steps.Data.DataType;
import org.mitre.pickledcanary.patterngenerator.output.steps.Step.StepType;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;
import org.mitre.pickledcanary.patterngenerator.generated.pc_grammar;
import org.mitre.pickledcanary.patterngenerator.generated.pc_grammarBaseVisitor;
import org.mitre.pickledcanary.search.Pattern;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class PCVisitor extends pc_grammarBaseVisitor<Void> {

	private static final boolean DEBUG = true;
	private static final String WILDCARD = "*";

	private final Program currentProgram;
	private final Address currentAddress;
	private final WildSleighAssembler assembler;
	private final TaskMonitor monitor;

	private final SleighLanguage language;

	// operand - binary representation tables
	private AllLookupTables tables;

	private final List<OrMultiState> orStates;
	private List<Step> steps;

	private final List<List<Step>> pushedSteps;
	private final List<AllLookupTables> pushedTables;

	private final Stack<Integer> byteStack;

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
		this.language = (SleighLanguage) currentProgram.getLanguage();
		WildSleighAssemblerBuilder builder = new WildSleighAssemblerBuilder(this.language);
		this.assembler = builder.getAssembler(new AssemblySelector(), currentProgram);

		this.tables = new AllLookupTables();
		this.pushedTables = new ArrayList<>();

		this.orStates = new ArrayList<>();
		this.steps = new ArrayList<>();
		this.pushedSteps = new ArrayList<>();
		this.byteStack = new Stack<>();

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

		this.steps.add(new AnyByteSequence(min, max, step, note));

		return null;
	}

	@Override
	public Void visitByte_match(pc_grammar.Byte_matchContext ctx) {
		visitChildren(ctx);
		this.steps.add(new Byte(this.byteStack.pop()));
		return null;
	}

	@Override
	public Void visitByte_string(pc_grammar.Byte_stringContext ctx) {

		var string_data = ctx.getText().strip();
		// Remove starting and ending '"' and translate escapes
		string_data = string_data.substring(1, string_data.length() - 1).translateEscapes();

		// Add a "Byte" for each character
		for (int x : string_data.toCharArray()) {
			this.steps.add(new Byte(x));
		}

		return null;
	}

	@Override
	public Void visitMasked_byte(pc_grammar.Masked_byteContext ctx) {
		visitChildren(ctx);
		var value = this.byteStack.pop();
		var mask = this.byteStack.pop();
		this.steps.add(new MaskedByte(mask, value));
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
		this.steps.add(new Label(label));
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
		}else {
			throw new RuntimeException("Can not have more than one META section!");
		}
		return null;
	}

	@Override
	public Void visitStart_or(pc_grammar.Start_orContext ctx) {
		// Add a new "split" step for this OR block.
		this.steps.add(new SplitMulti(this.steps.size() + 1));

		// Add a new OrState and reference the index of the split node for this Or block
		this.orStates.add(new OrMultiState(this.steps.size() - 1));
		return null;
	}

	@Override
	public Void visitMiddle_or(pc_grammar.Middle_orContext ctx) {
		// Add a new "jmp" step to (eventually) go to after the second "or" option.
		this.steps.add(new Jmp(this.steps.size() + 1));

		OrMultiState currentOrState = this.orStates.get(this.orStates.size() - 1);
		currentOrState.addMiddleStep(this.steps.size() - 1);

		// Update the split to have its next dest point to here after the jmp ending
		// the first option
		SplitMulti s = (SplitMulti) this.steps.get(currentOrState.getStartStep());
		s.addDest(this.steps.size());
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
			Jmp j = (Jmp) this.steps.get(jmp_idx);
			j.setDest(this.steps.size());
		}

		// If we have exactly two OR options, change from a SplitMulti to a Split
		if (middleSteps.size() == 1) {
			List<Integer> origDests =
				((SplitMulti) this.steps.get(currentOrState.getStartStep())).getDests();

			Split newSplit = new Split(origDests.get(0));
			newSplit.setDest2(origDests.get(1));
			this.steps.set(currentOrState.getStartStep(), newSplit);
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
		this.pushedSteps.add(this.steps);
		this.pushedTables.add(this.tables);
		this.steps = new ArrayList<>();
		this.tables = new AllLookupTables();
		return null;
	}

	@Override
	public Void visitEnd_negative_lookahead(pc_grammar.End_negative_lookaheadContext ctx) {
		// The final step of the not block should be a Match, so add it here.
		this.steps.add(new Match());

		// Generate the JSON for the inner-pattern (that will go within the
		// NegativeLookahead)
		JSONObject notPattern = this.getOutput();

		// Restore our "outer"/"main" steps and tables (which were saved at the
		// NotStartNode)
		this.steps = this.pushedSteps.remove(this.pushedSteps.size() - 1);
		this.tables = this.pushedTables.remove(this.pushedTables.size() - 1);

		// Add the NegativeLookahead step (including its inner-pattern) to our main set
		// of steps
		this.steps.add(new NegativeLookahead(notPattern));
		return null;
	}

	@Override
	public Void visitInstruction(pc_grammar.InstructionContext ctx) {
		if (DEBUG) {
			System.out.println("CURRENTLY PROCESSING: " + ctx.getText());
		}

		// Try to hint that we should clean memory before trying to do the following
		// memory-heavy stuff
		System.gc();

		Collection<AssemblyParseResult> parses = assembler.parseLine(ctx.getText())
				.stream()
				.filter(p -> !p.isError())
				.toList();

		if (parses.size() == 0) {
			raise_invalid_instruction_exception(ctx.getText());
		}

		LookupStep lookupStep = new LookupStep();

		for (AssemblyParseResult p : parses) {
			if (DEBUG) {
				System.err.println("parse: " + p);
			}
			AssemblyResolutionResults results = assembler.resolveTree(p, currentAddress);

			if (monitor.isCancelled()) {
				return null;
			}

			resultsLoop: for (AssemblyResolution res : results) {
				if (res instanceof WildAssemblyResolvedPatterns pats) {
					AssemblyPatternBlock assemblyPatternBlock = pats.getInstruction();
					if (DEBUG) {
						System.err.println(assemblyPatternBlock);
					}
					AssemblyPatternBlock noWildcardMask = assemblyPatternBlock.copy();

					// In some cases (e.g. "SHRD EAX,EBX,`Q1[..]`" in x86 32 bit) the instruction
					// returned by getInstruction is shorter than the location mask of some of that
					// instruction's operands. This block checks if that's the case and if so,
					// lengthens the instruction to fit its operands.
					int maxOperandLocationLength = pats.getOperandInfo()
							.stream()
							.map((x) -> x.location().getMaskAll().length)
							.max(Integer::compare)
							.orElse(0);
					
					if (noWildcardMask.getMaskAll().length < maxOperandLocationLength) {
						noWildcardMask = assemblyPatternBlock
								.combine(AssemblyPatternBlock.fromLength(maxOperandLocationLength));
					}

					HashMap<String, Object> operandChoices = new HashMap<String, Object>();
					for (WildOperandInfo info : pats.getOperandInfo()) {
						// remove masks of wildcards from the full instruction
						noWildcardMask = noWildcardMask.maskOut(info.location());

						// Just skip over instructions which have the same wildcard twice but with
						// different choices
						if (operandChoices.containsKey(info.wildcard())) {
							if (operandChoices.get(info.wildcard()) != info.choice()) {
								continue resultsLoop;
							}
						}
						else {
							operandChoices.put(info.wildcard(), info.choice());
						}
					}

					List<Integer> noWildcardMaskList = integerList(noWildcardMask.getMaskAll());
					List<Integer> noWildcardValList = integerList(noWildcardMask.getValsAll());

					// build data instruction for json
					// lookup step mask exists
					if (lookupStep.hasMask(noWildcardMaskList)) {
						Data data = lookupStep.getData(noWildcardMaskList);
						if (data.getType().equals(DataType.MaskAndChoose)) {
							LookupData lookupData = (LookupData) data;
							// if InstructionEncoding does not exist, make one
							if (!lookupData.hasChoice(noWildcardValList)) {
								InstructionEncoding ie = new InstructionEncoding(noWildcardValList);
								lookupData.putChoice(noWildcardValList, ie);
							}
							lookupStep.putData(noWildcardMaskList, lookupData);
						}
					}
					else {
						// no LookupData or InstructionEncoding -- make both
						InstructionEncoding ie = new InstructionEncoding(noWildcardValList);
						LookupData lookupData = new LookupData(noWildcardMaskList);
						lookupData.putChoice(noWildcardValList, ie);
						lookupStep.putData(noWildcardMaskList, lookupData);
					}

					// TODO: Remove wildcardIdx (here and in where it was being passed)
					var wildcardIdx = 0;
					for (WildOperandInfo assemblyOperandData : pats.getOperandInfo()) {
						if (assemblyOperandData.wildcard().compareTo(WILDCARD) == 0) {
// wildcardIdx += 1;
							continue;
						}

						List<Integer> wildcardMask =
							integerList(assemblyOperandData.location().getMaskAll());
						while (wildcardMask.size() < assemblyPatternBlock.length()) {
							wildcardMask.add(0);
						}

						// get key of table
						String tableKey = noWildcardMask.toString() + "_" + wildcardIdx;

						// It's not a scalar operand
						if (assemblyOperandData.choice() != null) {
							// get the current operand
							String operand = assemblyOperandData.choice().toString();

							var z = assemblyOperandData.location();

							// get binary masks and values of operand above
							// tableVals[0] is masks, tableVals[1] is values
							List<List<Integer>> tableVals = new ArrayList<List<Integer>>(2);
							tableVals.add(integerList(z.trim().getMaskAll()));
							tableVals.add(
								integerList(z.getMaskedValue(assemblyPatternBlock.getValsAll())
										.trim()
										.getValsAll()));

							/// ----------------------------
							// put mapping of operand to masks and values in table named tableKey
							if (DEBUG) {
								System.out.println(
									"Inserting mask and value of operand into table:\n\tTable name: " +
										tableKey + "\n\tOperand name: " + operand +
										"\n\tOperand mask: " + tableVals.get(0) +
										"\n\tOperand value: " + tableVals.get(1));
							}
							tables.put(tableKey, operand, tableVals.get(0), tableVals.get(1));
							/// ----------------------------
						}

						// add operand to json
						OperandMeta ot;
						if (assemblyOperandData.choice() == null) {
							ot = new ScalarOperandMeta(wildcardMask, assemblyOperandData.wildcard(),
								assemblyOperandData.expression());
						}
						else {
							ot = new FieldOperandMeta(wildcardMask, tableKey,
								assemblyOperandData.wildcard());
						}
						Data data = lookupStep.getData(noWildcardMaskList);
						if (data.getType().equals(DataType.MaskAndChoose)) {
							LookupData lookupData = (LookupData) data;
							InstructionEncoding ie = lookupData.getChoice(noWildcardValList);
							if (!ie.matches(ot)) {
								ie.addOperand(ot);
							}
						}
// wildcardIdx += 1;
					}
				}
			}
		}

		if (lookupStep.isEmpty()) {
			raise_invalid_instruction_exception(ctx.getText());
		}
		this.steps.add(lookupStep);

		return null;
	}

	void raise_invalid_instruction_exception(String instructionText) {
		if (instructionText.chars().filter(ch -> ch == '`').count() % 2 != 0) {
			throw new RuntimeException(
				"This line doesn't have a balanced number of '`' characters and didn't assemble to any instruction. Check this line: '" +
					instructionText + "'");
		}
		else {
			throw new RuntimeException(
				"An assembly instruction in your pattern (" + instructionText +
					") did not return any output. Make sure your assembly instructions" +
					" are valid or that you are using a binary with the same architecture.");
		}
	}

	/**
	 * Get a list of integers from a byte array.
	 * 
	 * <p>
	 * Bytes are interpreted as UNSIGNED integers.
	 * 
	 * @param input
	 * @return
	 */
	List<Integer> integerList(byte[] input) {
		List<Integer> out = new ArrayList<Integer>(input.length);
		for (int i = 0; i < input.length; i++) {
			out.add(java.lang.Byte.toUnsignedInt(input[i]));
		}
		return out;
	}

	/**
	 * Get raw JSON (without) any debug or compile info
	 * 
	 * @return
	 */
	public JSONObject getOutput() {
		JSONObject out = new JSONObject();
		out.put("tables", tables.getJson());

		JSONArray arr = new JSONArray();
		for (Step step : steps) {
			if (step.getStepType() == StepType.LOOKUP) {
				// replace temp table IDs with the actual table IDs
				((LookupStep) step).resolveTableIds(tables);
			}
			arr.put(step.getJson());
		}
		out.put("steps", arr);
		out.put("pattern_metadata", this.metadata);
		return out;
	}

	public String getJSON(boolean removeDebugInfo) {
		return this.getJSONObject(removeDebugInfo).toString();
	}
	
	public JSONObject getJSONObject(boolean removeDebugInfo) {
		var output = this.getOutput();

		if (!removeDebugInfo) {
			JSONObject compileInfo = new JSONObject();
			JSONObject sourceBinaryInfo = new JSONObject();
			sourceBinaryInfo.append("path", this.currentProgram.getExecutablePath());
			sourceBinaryInfo.append("md5", this.currentProgram.getExecutableMD5());
			sourceBinaryInfo.append("compiled_at_address", this.currentAddress);
			compileInfo.append("compiled_using_binary", sourceBinaryInfo);
			compileInfo.append("language_id", this.currentProgram.getLanguageID().getIdAsString());
			output.append("compile_info", compileInfo);
		}
		else {
			ArrayList<String> compileInfo = new ArrayList<>();
			output.put("compile_info", compileInfo);
		}

		return output;
	}

	public Pattern getPattern() {
		for (Step step : steps) {
			if (step.getStepType() == StepType.LOOKUP) {
				// replace temp table IDs with the actual table IDs
				((LookupStep) step).resolveTableIds(tables);
			}
		}
		return new Pattern(this.steps, tables.getPatternTables());
	}
	
	public Pattern getPatternWrapped() {
		Pattern patternCompiled = this.getPattern();
		Pattern start = Pattern.getDotStar();
		start.append(Pattern.getSaveStart());
		patternCompiled.prepend(start);
		patternCompiled.append(Pattern.getMatch());
		return patternCompiled;
	}
}
