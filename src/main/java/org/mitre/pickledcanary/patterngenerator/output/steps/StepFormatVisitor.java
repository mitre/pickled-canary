
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mitre.pickledcanary.assembler.Assembler;
import org.mitre.pickledcanary.assembler.Assemblers;
import org.mitre.pickledcanary.assembler.AssemblySelector;
import org.mitre.pickledcanary.assembler.AssemblySyntaxException;
import org.mitre.pickledcanary.assembler.sleigh.parse.AssemblyParseResult;
import org.mitre.pickledcanary.assembler.sleigh.sem.AssemblyOperandData;
import org.mitre.pickledcanary.assembler.sleigh.sem.AssemblyPatternBlock;
import org.mitre.pickledcanary.assembler.sleigh.sem.AssemblyResolution;
import org.mitre.pickledcanary.assembler.sleigh.sem.AssemblyResolutionResults;
import org.mitre.pickledcanary.assembler.sleigh.sem.AssemblyResolvedPatterns;
import org.mitre.pickledcanary.patterngenerator.output.FormatVisitor;
import org.mitre.pickledcanary.patterngenerator.output.steps.Data.DataType;
import org.mitre.pickledcanary.patterngenerator.output.steps.Step.StepType;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;
import org.mitre.pickledcanary.patterngenerator.output.utils.BitArray;
import org.mitre.pickledcanary.patterngenerator.output.utils.Utils;
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
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Visitor for to generate Step pattern.
 */
public class StepFormatVisitor implements FormatVisitor {
	private static final boolean DEBUG = false;
	private static final String WILDCARD = "*";

	private final Program currentProgram;
	private final Address currentAddress;
	private final Assembler assembler;
	private final AssemblyPatternBlock context;
	private final TaskMonitor monitor;

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
		this.currentProgram = currentProgram;
		this.currentAddress = currentAddress;
		this.monitor = monitor;
		this.assembler = Assemblers.getAssembler(currentProgram, new MyAssemblySelector());
		this.context = assembler.getContextAt(currentAddress).fillMask();

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

		// The binary representations of the instruction. Output of the assembler.
		AssemblyResolutionResults assemblyResults;
		try {
			// Now assemble a block. A block can be given as an array of strings, or a
			// string of newline-separated instructions.
			// This will patch each resulting instruction into the bound program in
			// sequence.
			instructionNode.populateAddressIntoWildcards(currentAddress);
			// Fill in AssemblyOperandData (metadata about operands) info here
			assemblyResults = assembler.resolveLine(currentAddress, instructionNode, context, monitor);
		} catch (AssemblySyntaxException e) {
			throw new RuntimeException("Got error trying to parse instruction: " + instructionNode.toString()
					+ "\n\nMake sure your assembly instructions are valid or that you are using a"
					+ " binary with the same architecture.");
		}

		if (monitor.isCancelled()) {
			return;
		}

		LookupStep lookupStep = new LookupStep();
		int validInstructionCount = 0;
		boolean allResultsForbidden = true;

		// loop through binary representations for a concrete instruction
		for (final AssemblyResolution assemblyResolution : assemblyResults) {
			if (assemblyResolution.isError()) {
				continue;
			}

			if (monitor.isCancelled()) {
				return;
			}

			final AssemblyResolvedPatterns assemblyResolvedPatterns = (AssemblyResolvedPatterns) assemblyResolution;
			final AssemblyPatternBlock assemblyPatternBlock = assemblyResolvedPatterns.getInstruction();
			List<AssemblyOperandData> assemblyOperandDataList = new ArrayList<>();
			if (!assemblyResolvedPatterns.checkNotForbidden().isError()) {
				allResultsForbidden = false;
				// get metadata about wildcarded operands to fill in json table
				assemblyOperandDataList = assemblyResolvedPatterns.getOperandData().getWildcardOperandData();
			}

			// if there are variables that are the same in an instruction, make sure
			// operands of those vars are the same before moving on
			HashMap<String, String> wildcardValues = new HashMap<>();
			boolean wildcardsMatch = true;
			for (AssemblyOperandData assemblyOperandData : assemblyOperandDataList) {
				String wildcardName = assemblyOperandData.getWildcardName();
				if (!wildcardName.equals(WILDCARD)) {
					if (!wildcardValues.containsKey(wildcardName)) {
						wildcardValues.put(wildcardName, assemblyOperandData.getOperandName());
					} else if (!wildcardValues.get(wildcardName).equals(assemblyOperandData.getOperandName())) {
						wildcardsMatch = false;
						break;
					}
				}
			}
			if (!wildcardsMatch) {
				continue;
			}

			validInstructionCount += 1;

			// Disassembler checking
			if (DEBUG) {
				Utils.assemblerDebug(currentProgram, currentAddress, assembler, assemblyPatternBlock.getVals());
			}

			BitArray fullMask = new BitArray(assemblyPatternBlock.getMask());

			// remove mask of "Q" operands from the fullMask
			BitArray noWildcardMask = fullMask;
			for (AssemblyOperandData assemblyOperandData : assemblyOperandDataList) {
				BitArray wildcardMask = new BitArray(assemblyOperandData.getMask());
				noWildcardMask = wildcardMask.not().and(noWildcardMask);
			}
			List<Integer> noWildcardMaskList = noWildcardMask.toIntList(); // mask for data in json

			// loop through binary representations of a concrete instruction (some
			// AssemblyResolutions contain more than one binary representation)
			for (byte[] val : assemblyPatternBlock.possibleVals()) {
				BitArray valBitArr = new BitArray(val);

				// value for InstructionEncoding in json
				BitArray noWildcardVal = valBitArr.and(noWildcardMask);
				List<Integer> noWildcardValList = noWildcardVal.toIntList();

				String valStr = valBitArr.getBinary();

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

				for (AssemblyOperandData assemblyOperandData : assemblyOperandDataList) {
					if (assemblyOperandData.getWildcardName().equals(WILDCARD)) {
						continue;
					}
					BitArray wildcardMask = new BitArray(assemblyOperandData.getMask());

					// get key of table
					BitArray wildcardMaskKey = new BitArray(assemblyOperandData.getMask().length);
					for (AssemblyOperandData aod : assemblyOperandDataList) {
						wildcardMaskKey = wildcardMaskKey.or(new BitArray(aod.getMask()));
					}
					String maskStr = wildcardMaskKey.getBinary();
					String tableKey = Utils.maskToX(maskStr, valStr) + "_" + assemblyOperandData.getWildcardIdx();

					int operandType = assemblyOperandData.getOperandType();

					if (!OperandType.isScalar(operandType)) {
						// get the current operand
						String operand = assemblyOperandData.getOperandName();
						// get binary masks and values of operand above
						// tableVals[0] is masks, tableVals[1] is values
						List<List<Integer>> tableVals = Utils.binToDecMaskVal(wildcardMask.toByteArray(), val);

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
					if (OperandType.isScalar(operandType)) {
						ot = new ScalarOperandMeta(wildcardMask.toIntList(), assemblyOperandData.getWildcardName(),
								assemblyOperandData.getWildcardIdx(), assemblyOperandData.getExpression());
					} else {
						ot = new FieldOperandMeta(wildcardMask.toIntList(), tableKey,
								assemblyOperandData.getWildcardName(), assemblyOperandData.getWildcardIdx());
					}
					Data data = lookupStep.getData(noWildcardMaskList);
					if (data.type.equals(DataType.MaskAndChoose)) {
						LookupData lookupData = (LookupData) data;
						InstructionEncoding ie = lookupData.getChoice(noWildcardValList);
						if (!ie.matches(ot)) {
							ie.addOperand(ot);
						}
					}
				}
			}
		}

		this.steps.add(lookupStep);

		if (validInstructionCount == 0) {
			throw new RuntimeException("An assembly instruction in your pattern (" + instructionNode.toString()
					+ ") did not return any output. Make sure your assembly instructions"
					+ " are valid or that you are using a binary with the same architecture.");
		}

		if (allResultsForbidden) {
			System.out.println("WARNING: All results for this step are forbidden. Verify that your output is correct.");
		}
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

	/**
	 * The only difference between this class and the one it extends is the fact
	 * that this one only provides an empty string in its AssemblySyntaxException
	 * rather than a complete listing of all the errors
	 */
	static class MyAssemblySelector extends AssemblySelector {
		@Override
		public Collection<AssemblyParseResult> filterParse(Collection<AssemblyParseResult> parse)
				throws AssemblySyntaxException {
			boolean gotOne = false;
			for (AssemblyParseResult pr : parse) {
				if (pr.isError()) {
					// syntaxErrors.add(pr);
				} else {
					gotOne = true;
				}
			}
			if (!gotOne) {
				throw new AssemblySyntaxException("");
			}
			return parse;
		}
	}
}
