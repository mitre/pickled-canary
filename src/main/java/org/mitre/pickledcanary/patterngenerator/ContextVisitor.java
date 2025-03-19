// Copyright (C) 2025 The MITRE Corporation All Rights Reserved
package org.mitre.pickledcanary.patterngenerator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Stack;
import java.util.TreeMap;

import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.patterngenerator.PCVisitor.PatternContext;
import org.mitre.pickledcanary.patterngenerator.output.steps.Context;
import org.mitre.pickledcanary.patterngenerator.output.steps.Jmp;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupStep;
import org.mitre.pickledcanary.patterngenerator.output.steps.SplitMulti;
import org.mitre.pickledcanary.patterngenerator.output.steps.Step;
import org.mitre.pickledcanary.patterngenerator.output.utils.LookupStepBuilder;

import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults;
import ghidra.app.plugin.assembler.sleigh.sem.DefaultAssemblyResolvedPatterns;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.asm.wild.WildSleighAssembler;
import ghidra.asm.wild.WildSleighAssemblerBuilder;
import ghidra.asm.wild.sem.DefaultWildAssemblyResolvedPatterns;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.DisassemblerContextAdapter;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

/**
 * This class contains the second step to creating the generated pattern. This step assembles
 * all the assembly instruction steps, gathers the context for each instruction, and generates
 * new branches and steps to make the pattern context aware.
 */
public class ContextVisitor {
	private final Program currentProgram;
	private Address currentAddress;
	private PatternContext currentContext;
	private final WildSleighAssembler assembler;
	private SleighLanguage language;
	private TaskMonitor monitor;
	
	protected Stack<BranchHead> contextStack; // tracks new context branches that will be handled later
	protected Stack<Integer> contextOrStack; // tracks where the start of the split steps
	protected PatternContext contextAwareContext; // contains the generated pattern steps
	protected RegisterValue asmCurrentContext; // current context used for assembling instructions
	protected RegisterValue noFlowSave = null; // the context that should be reverted to in a noflow situation

	private ResultMap variantCtx;
	
	private LinkedHashMap<String, ArrayList<ContextDebugEncoding>> contextDebugInfo;

	public record ContextDebugEncoding(byte[] encodingMask, byte[] encodingValue, RegisterValue inputContext, RegisterValue outputContext) {};
	
	private record ContextChanges(RegisterValue localCtx, AddressMap globalCtx) {};

	private record ResultMap(HashMap<AssemblyParseResult, PatternMap> map) {
		ResultMap() {
			this(new HashMap<>());
		}
	};

	private record PatternMap(HashMap<DefaultWildAssemblyResolvedPatterns, AddressMap> map) {
		PatternMap() {
			this(new HashMap<>());
		}
	};

	private record AddressMap(HashMap<Address, RegisterValue> map) {
		AddressMap() {
			this(new HashMap<>());
		}
	};

	private class BranchHead {
		LookupStep firstStep;
		RegisterValue context;
		RegisterValue noFlowContext;
		int startIdx;

		/**
		 * Represents the start of a branch in the generated pattern.
		 * @param firstStep an instruction that should be inserted as the first instruction in the branch; null if no instruction needs to be inserted, i.e. the first instruction of the branch is located at startIdx
		 * @param context context used to assemble the first instruction in the branch
		 * @param noFlowContext the context that should be reverted to if the start context is a noflow context; null if start context is not noflow
		 * @param startIdx index of the output of the first visitor where the first step of the branch begins
		 */
		private BranchHead(LookupStep firstStep, RegisterValue context, RegisterValue noFlowContext, int startIdx) {
			this.firstStep = firstStep;
			this.context = context;
			this.noFlowContext = noFlowContext;
			this.startIdx = startIdx;
		}
	}

	// Needed to reimplement this class, luckily it's small
	static class ContextAdapter implements DisassemblerContextAdapter {
		private final RegisterValue contextIn;
		private final Map<Address, RegisterValue> contextsOut = new TreeMap<>();

		public ContextAdapter(RegisterValue contextIn) {
			this.contextIn = contextIn;
		}

		@Override
		public RegisterValue getRegisterValue(Register register) {
			if (register.getBaseRegister() == contextIn.getRegister()) {
				return contextIn.getRegisterValue(register);
			}
			return null;
		}

		@Override
		public void setFutureRegisterValue(Address address, RegisterValue value) {
			RegisterValue current = contextsOut.get(address);
			RegisterValue combined = current == null ? value : current.combineValues(value);
			contextsOut.put(address, combined);
		}

		public void addFlow(ProgramContext progCtx, Address after) {
			contextsOut.put(after, progCtx.getFlowValue(contextIn));
		}
	}

	protected static void raiseInvalidInstructionException(LookupStep lookupStep) {
		String instructionText = lookupStep.getInstructionText();

		if (instructionText.chars().filter(ch -> ch == '`').count() % 2 != 0) {
			throw new QueryParseException(
					"This line doesn't have a balanced number of '`' characters and didn't assemble to any instruction",
					lookupStep);
		}
		throw new QueryParseException(
				"An assembly instruction in your pattern (" + instructionText
						+ ") did not return any output. Make sure your assembly instructions"
						+ " are valid or that you are using a binary with the same architecture.",
				lookupStep);
	}

	ContextVisitor(Program currentProgram, Address currentAddress, TaskMonitor monitor, PatternContext currentContext) {
		this.contextStack = new Stack<>();
		this.contextOrStack = new Stack<>();
		this.contextAwareContext = new PatternContext();
		
		this.currentProgram = currentProgram;
		this.currentAddress = currentAddress;
		this.currentContext = currentContext;
		this.language = (SleighLanguage) currentProgram.getLanguage();
		WildSleighAssemblerBuilder builder = new WildSleighAssemblerBuilder(language);
		this.assembler = builder.getAssembler(new AssemblySelector(), currentProgram);
		this.monitor = monitor;
		
		contextDebugInfo = new LinkedHashMap<>();
	}
	
	public LinkedHashMap<String, ArrayList<ContextDebugEncoding>> getContextDebugInfo() {
		return this.contextDebugInfo;
	}
	
	/**
	 * After the user pattern is passed through the first visitor above, run the output through this
	 * second visitor to make the generated pattern context-aware.
	 */
	public PatternContext makeContextAware() {
		// set first context
		RegisterValue initialContext = currentProgram.getProgramContext()
				.getDisassemblyContext(currentAddress);
		this.contextStack.add(new BranchHead(null, initialContext, null, 0));
		while (!this.contextStack.isEmpty()) {
			// process each context branch
			// TODO: replace with removeLast() when we have full JDK21 support
			BranchHead branch = this.contextStack.remove(this.contextStack.size() - 1);
			if (branch.firstStep != null) {
				this.contextAwareContext.getSteps().add(branch.firstStep);
			}
			asmCurrentContext = branch.context;
			for (int i = branch.startIdx; i < currentContext.getSteps().size(); i++) {
				// process each instruction within the context branch
				Step step = currentContext.getSteps().get(i);
				switch (step.getStepType()) {
					case SPLITMULTI:
						int nextInst = visit((SplitMulti) step);
						i = nextInst - 1;
						break;
					case JMP:
						nextInst = visit((Jmp) step);
						i = nextInst - 1;
						break;
					case LOOKUP:
						visit(i, ((LookupStep) step).copy());
						if (branch.noFlowContext != null) {
							// if we are at the beginning of a branch and there is a start context, set the context
							asmCurrentContext = handleNoFlows(branch.noFlowContext, asmCurrentContext);
							branch.noFlowContext = null;
							noFlowSave = null;
						}
						break;
					case CONTEXT:
						visit((Context) step);
						branch.noFlowContext = null; // user overrides all contexts
						break;
					default:
						visit(step);
						if (branch.noFlowContext != null) {
							// if we are at the beginning of a branch and there is a start context, set the context
							asmCurrentContext = handleNoFlows(branch.noFlowContext, asmCurrentContext);
							branch.noFlowContext = null;
							noFlowSave = null;
						}
				}
				
			}
			if (!this.contextStack.isEmpty()) {
				// there are more context branches to handle
				// add a jump, which will later be filled in with dest of end of pattern
				this.contextAwareContext.getSteps().add(new Jmp(0));
				// add the next destination for a Split or SplitMulti block
				// TODO: replace with removeLast() when we have full JDK21 support
				int correspondingSplitIndex = this.contextOrStack.remove(this.contextOrStack.size()-1);
				SplitMulti sm =
					(SplitMulti) this.contextAwareContext.getSteps().get(correspondingSplitIndex);
				sm.addDest(this.contextAwareContext.getSteps().size());
			}
		}

		for (Step nextStep : this.contextAwareContext.getSteps()) {
			if (nextStep.getStepType() == Step.StepType.JMP) {
				// all jumps should go to the end of the pattern
				((Jmp) nextStep).setDest(this.contextAwareContext.getSteps().size());
			}
		}

		return this.contextAwareContext;
	}

	// #region Visit methods
	/**
	 * Handles split step.
	 * @param splitMultiStep split step to process
	 * @return index of the step in the output of the first visitor from where the next branch
	 * should begin
	 */
	private int visit(SplitMulti splitMultiStep) {
		// when there is a split, we will process the first branch and put the other branches in a
		// stack to process them after the first branch
		for (int i = splitMultiStep.getDests().size() - 1; i > 0; i--) {
			this.contextOrStack.add(this.contextAwareContext.getSteps().size());
			this.contextStack
					.add(new BranchHead(null, asmCurrentContext, noFlowSave, splitMultiStep.getDests().get(i)));
		}
		this.contextAwareContext.getSteps()
				.add(new SplitMulti(this.contextAwareContext.getSteps().size() + 1));
		return splitMultiStep.getDests().get(0);
	}

	/**
	 * Handles jump step.
	 * @param jmpStep jump step to process
	 * @return step in output of the first visitor to jump to in order to continue processing the
	 * current branch
	 */
	private int visit(Jmp jmpStep) {
		return jmpStep.getDest();
	}

	/**
	 * Handles assembly instruction step.
	 * @param tokenIdx step number of this step in the output of the first visitor
	 * @param lookupStep the instruction to assemble
	 */
	private void visit(int tokenIdx, LookupStep lookupStep) {
		contextDebugInfo.put(lookupStep.getLineNumber() + ": " + lookupStep.getInstructionText(), new ArrayList<>());
		
		List<LookupStep> lookupSteps = assembleInstruction(lookupStep);
		if (lookupSteps == null) {
			return;
		}

		if (lookupSteps.size() > 1) {
			// Each lookup step contains all the valid encodings for a certain output context.
			// Because there is more than one output context, put a split in the results to
			// split over the different contexts
			this.contextAwareContext.getSteps().add(new SplitMulti(this.contextAwareContext.getSteps().size() + 1));
		}

		// TODO: replace with getFirst() when we have full JDK21 support
		RegisterValue firstLookupStepContext = lookupSteps.get(0).getOutputContext();
		// Determine if the next context is no flow
		boolean hasNoFlow = checkNoFlow(asmCurrentContext, firstLookupStepContext);

		if (hasNoFlow || noFlowSave == null) {
			// hasNoFlow is true & noFlowSave is null -> we are encountering a noflow, so save current context and set the noflow context as next context
			// hasNoFlow is true & noFlowSave is not null -> the previous and next contexts are noflows, original context already saved, so no need to do that
			// hasNoFlow is false & noFlowSave is null -> nothing related to noflow is happening; just set the next global context
			if (noFlowSave == null && hasNoFlow) {
				noFlowSave = asmCurrentContext;
			}
			asmCurrentContext = firstLookupStepContext;

		}
		else {
			// revert the noflow context to the original context
			asmCurrentContext = handleNoFlows(noFlowSave, firstLookupStepContext);
			noFlowSave = null;
		}

		// add first context branch to result
		// TODO: replace with getFirst() when we have full JDK21 support
		this.contextAwareContext.getSteps().add(lookupSteps.get(0));

		// if there are more branches, add them to a stack to process later
		for (int i = 1; i < lookupSteps.size(); i++) {
			this.contextOrStack.add(this.contextAwareContext.getSteps().size() - 2);
			this.contextStack
					.add(new BranchHead(lookupSteps.get(i), lookupSteps.get(i).getOutputContext(), noFlowSave, tokenIdx + 1));
		}
	}

	/**
	 * Handles step that allows user to override the current context.
	 * @param contextStep context step to process
	 */
	private void visit(Context contextStep) {
		for (RegisterValue contextVar : contextStep.getContextVars()) {
			// asmCurrentContext always contains the full context register
			// We set the specified value for the specified context variable in that context register
			this.asmCurrentContext =
				this.asmCurrentContext.assign(contextVar.getRegister(), contextVar);
		}
	}

	/**
	 * Handles all other steps not listed above.
	 * @param step step to process
	 */
	private void visit(Step step) {
		this.contextAwareContext.getSteps().add(step);
	}
	// #endregion

	/**
	 * Assembles an assembly instruction.
	 * @param lookupStep the lookup step containing the instruction to assemble
	 * @return a list of lookup steps filled in with encodings. Each LookupStep contains a
	 * different output context (new branch for each context)
	 */
	private List<LookupStep> assembleInstruction(LookupStep lookupStep) {
		Collection<AssemblyParseResult> parses = assembler
				.parseLine(lookupStep.getInstructionText())
				.stream()
				.filter(p -> {
					if (PickledCanary.DEBUG && p.isError()) {
						System.err.println("Error in AssemblyParseResult: " + p);
					}
					return !p.isError();
				})
				.toList();
		if (parses.isEmpty()) {
			raiseInvalidInstructionException(lookupStep);
		}

		List<LookupStep> lookupSteps = this.makeLookupStepFromParseResults(lookupStep, parses);
		if (lookupSteps == null) {
			return null;
		}
		if (lookupSteps.isEmpty()) {
			raiseInvalidInstructionException(lookupStep);
		}

		return lookupSteps;
	}

	/**
	 * Assembles an assembly instruction.
	 * @param lookupStep the lookup step containing the instruction to assemble
	 * @param parses the parsed data of the instruction to assemble
	 * @return a list of lookup steps filled in with encodings. Each LookupStep contains a
	 * different output context (new branch for each context)
	 */
	private List<LookupStep> makeLookupStepFromParseResults(LookupStep lookupStep,
			Collection<AssemblyParseResult> parses) {
		RegisterValue inputContext = this.asmCurrentContext;
		AssemblyPatternBlock assemblerCtx = AssemblyPatternBlock
				.fromRegisterValue(this.asmCurrentContext)
				// TODO: Remove this when we want to have wildcard context in Ghidra versions 11.3 and up
				.fillMask();

		System.err.println("Context going into assembler: " + assemblerCtx);
		this.variantCtx = new ResultMap();

		// maps output context to a LookupStep containing encodings that produce the output context
		LinkedHashMap<RegisterValue, LookupStepBuilder> encodingResultsBuilders = new LinkedHashMap<>();
		ArrayList<ContextDebugEncoding> cdes = contextDebugInfo.get(lookupStep.getLineNumber() + ": " + lookupStep.getInstructionText());
		for (AssemblyParseResult p : parses) {
			if (PickledCanary.DEBUG) {
				// Print each instruction variant
				System.err.println("parse = " + p);
			}

			AssemblyResolutionResults results;

			// Resolve each instruction variant to get the encodings
			// All variants should use the same input context (global context) for resolution
			// Encodings for variants which are not valid in the provided context are filtered out by the assembler
			results = assembler.resolveTree(p, currentAddress, assemblerCtx);

			if (monitor.isCancelled()) {
				// Yield if user wants to cancel operation
				return null;
			}

			PatternMap encodingCtx = new PatternMap();

			for (AssemblyResolution res : results) {
				if (res instanceof DefaultWildAssemblyResolvedPatterns pats) {
					// We must compute the context changes (if any) for every pats
					// The instruction encodings may affect the global context
					ContextChanges contextChanges = getContextChanges(pats, this.asmCurrentContext);
					System.err.println("Printing local context: " + contextChanges.localCtx());

					AddressMap encodingContextChanges = contextChanges.globalCtx();

					encodingCtx.map.put(pats, encodingContextChanges);

					for (Address a : encodingContextChanges.map.keySet()) {
						// there are context changes to process
						// TODO: pickled canary currently assumes that all context changes
						// occur in the next instruction. This may not always be the case, as
						// an instruction can set a context for any address
						RegisterValue outputContext = encodingContextChanges.map.get(a);
						if (!encodingResultsBuilders.containsKey(outputContext)) {
							LookupStep lookupStepCopy = lookupStep.copy();
							lookupStepCopy.setOutputContext(outputContext);
							cdes.add(new ContextDebugEncoding(pats.getInstruction().getMaskAll(), pats.getInstruction().getValsAll(), inputContext, outputContext));
							encodingResultsBuilders.put(outputContext, new LookupStepBuilder(
								lookupStepCopy, this.contextAwareContext.getTables()));

						}
						encodingResultsBuilders.get(outputContext)
								.addAssemblyPattern(pats, contextChanges.localCtx());
					}
					if (encodingContextChanges.map.isEmpty()) {
						// no context changes means the current context will be the next context
						if (!encodingResultsBuilders.containsKey(asmCurrentContext)) {
							LookupStep lookupStepCopy = lookupStep.copy();
							lookupStepCopy.setOutputContext(asmCurrentContext);
							cdes.add(new ContextDebugEncoding(pats.getInstruction().getMaskAll(), pats.getInstruction().getValsAll(), inputContext, asmCurrentContext));
							encodingResultsBuilders.put(asmCurrentContext,
								new LookupStepBuilder(lookupStepCopy,
									this.contextAwareContext.getTables()));

						}
						encodingResultsBuilders.get(asmCurrentContext).addAssemblyPattern(pats, contextChanges.localCtx());
					}
				}
			}
			variantCtx.map.put(p, encodingCtx);
		}
		List<LookupStep> encodingResults = new ArrayList<>();
		for (LookupStepBuilder lsb : encodingResultsBuilders.values()) {
			encodingResults.add(lsb.buildLookupStep());
		}
		printContextChanges(this.variantCtx);
		return encodingResults;
	}

	/**
	 * Gets the changes to context produced by an encoding.
	 * @param pats an instruction encoding
	 * @param inputCtx the context used to aseemble to get the instruction encoding
	 * @return list of context changes produced by encoding
	 */
	public ContextChanges getContextChanges(DefaultAssemblyResolvedPatterns pats,
			RegisterValue inputCtx) {
		ContextAdapter contextAdapter = new ContextAdapter(inputCtx);
		ByteMemBufferImpl buffer = new ByteMemBufferImpl(currentAddress,
			pats.getInstruction().getVals(), language.isBigEndian());

		RegisterValue localCtx = null;
		// Use the language to parse the context changes for each encoding
		// We might be disassembling the instruction we just assembled
		try {
			SleighInstructionPrototype proto =
				(SleighInstructionPrototype) language.parse(buffer, contextAdapter, false);
			// Get the local context changes from the prototype
			// While we retrieve this for every encoding, we don't always need it
			localCtx = proto.getParserContext(buffer, contextAdapter).getContextRegisterValue();
		}
		catch (InsufficientBytesException | UnknownInstructionException
				| MemoryAccessException e) {
			e.printStackTrace();
		}

		// A single encoding may change the global context at multiple addresses
		AddressMap globalCtx = new AddressMap();

		for (Entry<Address, RegisterValue> ent : contextAdapter.contextsOut.entrySet()) {
			globalCtx.map.put(ent.getKey(), inputCtx.combineValues(ent.getValue()));
		}
		return new ContextChanges(localCtx, globalCtx);
	}

	private void printContextChanges(ResultMap variantCtx) {
		System.err.print(System.lineSeparator());

		for (AssemblyParseResult parseResult : variantCtx.map.keySet()) {
			System.err.println("Instruction variant: " + parseResult);

			PatternMap encodingCtx = variantCtx.map.get(parseResult);

			for (DefaultWildAssemblyResolvedPatterns resolvedPats : encodingCtx.map.keySet()) {
				System.err.println("Instruction encoding: " + resolvedPats.getInstruction());

				AddressMap addressCtx = encodingCtx.map.get(resolvedPats);

				for (Address address : addressCtx.map.keySet()) {
					System.err.println("Context: " + addressCtx.map.get(address) +
						" set at address: " + address);
				}
				System.err.print(System.lineSeparator());
			}
		}
	}

	/**
	 * Determines if a context is noflow.
	 * @param currCtx the context used to produce nextCtx
	 * @param nextCtx the context to check if it is noflow
	 * @return true if nextCtx is nowflow; false otherwise
	 */
	private boolean checkNoFlow(RegisterValue currCtx, RegisterValue nextCtx) {
		// TODO: Use cached contextreg and context variables
		Register contextReg = language.getContextBaseRegister();

		for (Register contextVar : contextReg.getChildRegisters()) {
			if (!contextVar.followsFlow() && !nextCtx.getRegisterValue(contextVar)
					.equals(currCtx.getRegisterValue(contextVar))) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Undo the context in a noflow instruction. We aren't reverting the noflow variables in the next context.
	 * Instead, we update the saved context with only the variables that follow flow from the next context.
	 * @param saveCtx the context to revert to
	 * @param nextCtx the current context
	 * @return the context to revert to
	 */
	private RegisterValue handleNoFlows(RegisterValue saveCtx, RegisterValue nextCtx) {
		// TODO: Use cached contextreg and context variables
		Register contextReg = language.getContextBaseRegister();

		for (Register contextVar : contextReg.getChildRegisters()) {
			if (contextVar.followsFlow()) {
				saveCtx = saveCtx.assign(contextVar, nextCtx.getRegisterValue(contextVar));
			}
		}
		return saveCtx;
	}
}
