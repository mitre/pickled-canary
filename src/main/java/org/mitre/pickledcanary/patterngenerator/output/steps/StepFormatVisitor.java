
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.asm.wild.WildOperandInfo;
import ghidra.asm.wild.WildSleighAssembler;
import ghidra.asm.wild.WildSleighAssemblerBuilder;
import ghidra.asm.wild.sem.WildAssemblyResolvedPatterns;
import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults;
import org.mitre.pickledcanary.patterngenerator.output.FormatVisitor;
import org.mitre.pickledcanary.patterngenerator.output.steps.Data.DataType;
import org.mitre.pickledcanary.patterngenerator.output.steps.Step.StepType;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;
import org.mitre.pickledcanary.querylanguage.lexer.ast.AnyBytesNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.ByteNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.InstructionNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.LabelNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.MaskedByteNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.MetaNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.NotEndNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.NotStartNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.OrEndNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.OrMiddleNode;
import org.mitre.pickledcanary.querylanguage.lexer.ast.OrStartNode;
import org.mitre.pickledcanary.search.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Visitor for to generate Step pattern.
 */
public class StepFormatVisitor implements FormatVisitor {
	private static final boolean DEBUG = true;
	private static final String WILDCARD = "*";

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

	private JSONObject metadata;

	/**
	 * Construct visitor to build Step output.
	 *
	 * @param currentProgram
	 * @param currentAddress
	 * @param monitor
	 */
	public StepFormatVisitor(final Program currentProgram, final Address currentAddress, final TaskMonitor monitor) {
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

		this.metadata = new JSONObject();
	}

	@Override
	public void visit(final InstructionNode instructionNode) {
		if (DEBUG) {
			System.out.println("CURRENTLY PROCESSING: " + instructionNode.toString());
		}

		// Try to hint that we should clean memory before trying to do the following
		// memory-heavy stuff
		System.gc();

		Collection<AssemblyParseResult> parses = assembler.parseLine(instructionNode.getInstructionText()).stream()
				.filter(p -> !p.isError()).toList();

		if (parses.size() == 0) {
			throw new RuntimeException("An assembly instruction in your pattern (" + instructionNode.toString()
					+ ") did not return any output. Make sure your assembly instructions"
					+ " are valid or that you are using a binary with the same architecture.");
		}

		LookupStep lookupStep = new LookupStep();

		for (AssemblyParseResult p : parses) {
			System.err.println("parse: " + p);
			AssemblyResolutionResults results = assembler.resolveTree(p, currentAddress);

			if (monitor.isCancelled()) {
				return;
			}

			resultsLoop:
			for (AssemblyResolution res : results) {
				if (res instanceof WildAssemblyResolvedPatterns pats) {
					AssemblyPatternBlock assemblyPatternBlock = pats.getInstruction();
					System.err.println(assemblyPatternBlock);

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
					System.out.println(maxOperandLocationLength);
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
						} else {
							operandChoices.put(info.wildcard(), info.choice());
						}
					}

					List<Integer> noWildcardMaskList = integerList(noWildcardMask.getMaskAll());
					List<Integer> noWildcardValList = integerList(noWildcardMask.getValsAll());

					// build data instruction for json
					// lookup step mask exists
					if (lookupStep.hasMask(noWildcardMaskList)) {
						Data data = lookupStep.getData(noWildcardMaskList);
						if (data.type.equals(DataType.MaskAndChoose)) {
							LookupData lookupData = (LookupData) data;
							// if InstructionEncoding does not exist, make one
							if (!lookupData.hasChoice(noWildcardValList)) {
								InstructionEncoding ie = new InstructionEncoding(noWildcardValList);
								lookupData.putChoice(noWildcardValList, ie);
							}
							lookupStep.putData(noWildcardMaskList, lookupData);
						}
					} else {
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
//							wildcardIdx += 1;
							continue;
						}

						List<Integer> wildcardMask = integerList(assemblyOperandData.location().getMaskAll());
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
							tableVals.add(integerList(z.getMaskedValue(assemblyPatternBlock.getValsAll()).trim().getValsAll()));

							/// ----------------------------
							// put mapping of operand to masks and values in table named tableKey
							if (DEBUG) {
								System.out.println("Inserting mask and value of operand into table:\n\tTable name: "
										+ tableKey + "\n\tOperand name: " + operand + "\n\tOperand mask: "
										+ tableVals.get(0) + "\n\tOperand value: " + tableVals.get(1));
							}
							tables.put(tableKey, operand, tableVals.get(0), tableVals.get(1));
							/// ----------------------------
						}

						// add operand to json
						OperandMeta ot;
						if (assemblyOperandData.choice() == null) {
							ot = new ScalarOperandMeta(wildcardMask, assemblyOperandData.wildcard(),
									assemblyOperandData.expression());
						} else {
							ot = new FieldOperandMeta(wildcardMask, tableKey, assemblyOperandData.wildcard());
						}
						Data data = lookupStep.getData(noWildcardMaskList);
						if (data.type.equals(DataType.MaskAndChoose)) {
							LookupData lookupData = (LookupData) data;
							InstructionEncoding ie = lookupData.getChoice(noWildcardValList);
							if (!ie.matches(ot)) {
								ie.addOperand(ot);
							}
						}
//						wildcardIdx += 1;
					}
				}
			}
		}

		if (lookupStep.isEmpty()) {
			throw new RuntimeException("An assembly instruction in your pattern (" + instructionNode.toString()
			+ ") did not return any output. Make sure your assembly instructions"
			+ " are valid or that you are using a binary with the same architecture.");
		}
		this.steps.add(lookupStep);
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
	List<Integer> integerList(byte [] input) {
		List<Integer> out = new ArrayList<Integer>(input.length);
		for (int i = 0; i < input.length; i++) {
			out.add(java.lang.Byte.toUnsignedInt(input[i]));
		}
		return out;
	}

	// create json output for AnyByte instructions
	@Override
	public void visit(final AnyBytesNode anyBytesNode) {
		String note = anyBytesNode.toString();
		this.steps.add(
				new AnyByteSequence(anyBytesNode.getStart(), anyBytesNode.getEnd(), anyBytesNode.getInterval(), note));
	}

	@Override
	public void visit(final OrStartNode orStartNode) {
		// Add a new "split" step for this OR block.
		this.steps.add(new SplitMulti(this.steps.size() + 1));

		// Add a new OrState and reference the index of the split node for this Or block
		this.orStates.add(new OrMultiState(this.steps.size() - 1));
	}

	@Override
	public void visit(final OrMiddleNode orMiddleNode) {
		// Add a new "jmp" step to (eventually) go to after the second "or" option.
		this.steps.add(new Jmp(this.steps.size() + 1));

		OrMultiState currentOrState = this.orStates.get(this.orStates.size() - 1);
		currentOrState.addMiddleStep(this.steps.size() - 1);

		// Update the split to have its next dest point to here after the jmp ending
		// the first option
		SplitMulti s = (SplitMulti) this.steps.get(currentOrState.getStartStep());
		s.addDest(this.steps.size());
	}

	@Override
	public void visit(final OrEndNode orEndNode) {

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
			List<Integer> origDests = ((SplitMulti) this.steps.get(currentOrState.getStartStep())).getDests();

			Split newSplit = new Split(origDests.get(0));
			newSplit.setDest2(origDests.get(1));
			this.steps.set(currentOrState.getStartStep(), newSplit);
		}
	}

	@Override
	public void visit(final ByteNode byteNode) {
		this.steps.add(new Byte(byteNode.value()));
	}

	@Override
	public void visit(final MaskedByteNode maskedByteNode) {
		this.steps.add(new MaskedByte(maskedByteNode.mask(), maskedByteNode.value()));
	}

	@Override
	public void visit(final MetaNode metaNode) {
		this.metadata = new JSONObject(metaNode.getValue());
	}

	@Override
	public void visit(final NotStartNode notStartNode) {
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
	}

	@Override
	public void visit(final NotEndNode notEndNode) {
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
	}

	@Override
	public void visit(LabelNode labelNode) {
		this.steps.add(new Label(labelNode.name()));
	}

	// get json output that is produced
	// call this method after all json generated with methods above
	@Override
	public JSONObject getOutput() {
		JSONObject out = new JSONObject();
		out.put("tables", tables.getJson());

		JSONArray arr = new JSONArray();
		for (Step step : steps) {
			if (step.stepType == StepType.LOOKUP) {
				// replace temp table IDs with the actual table IDs
				((LookupStep) step).resolveTableIds(tables);
			}
			arr.put(step.getJson());
		}
		out.put("steps", arr);
		out.put("pattern_metadata", this.metadata);
		return out;
	}

	@Override
	public Pattern getPattern() {
		for (Step step : steps) {
			if (step.stepType == StepType.LOOKUP) {
				// replace temp table IDs with the actual table IDs
				((LookupStep) step).resolveTableIds(tables);
			}
		}
		return new Pattern(this.steps, tables.getPatternTables());
	}
}
