// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.utils;

import java.util.List;
import java.util.Set;

import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.patterngenerator.output.steps.Data;
import org.mitre.pickledcanary.patterngenerator.output.steps.FieldOperandMeta;
import org.mitre.pickledcanary.patterngenerator.output.steps.InstructionEncoding;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupData;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupStep;
import org.mitre.pickledcanary.patterngenerator.output.steps.OperandMeta;
import org.mitre.pickledcanary.patterngenerator.output.steps.ScalarOperandMeta;
import org.mitre.pickledcanary.util.PCAssemblerUtils;
import org.mitre.pickledcanary.util.PCBytes;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.processors.sleigh.ContextCache;
import ghidra.asm.wild.WildOperandInfo;
import ghidra.asm.wild.sem.WildAssemblyResolvedPatterns;
import ghidra.program.model.lang.DisassemblerContextAdapter;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

/**
 * Utility class for building up {@link LookupStep} objects from resolved assembly patterns.
 */
public class LookupStepBuilder {
	private final AllLookupTables tables;
	private final LookupStep lookupStep;

	/**
	 * Create a new instance of this builder.
	 * @param lookupStep step in which to populate instruction encodings
	 * @param tables reference to the lookup tables so they can be updated as patterns are parsed
	 */
	public LookupStepBuilder(LookupStep lookupStep, AllLookupTables tables) {
		this.tables = tables;
		this.lookupStep = lookupStep;
	}

	/**
	 * Add an assembly encoding to the LookupStep.
	 * @param pats the assembly encoding
	 * @param context input context
	 */
	public void addAssemblyPattern(WildAssemblyResolvedPatterns pats, RegisterValue context) {
		AssemblyPatternBlock assemblyPatternBlock = pats.getInstruction();
		Set<WildOperandInfo> operandInfos = pats.getOperandInfo();

		if (PickledCanary.DEBUG) {
			System.err.println("assemblyPatternBlock = " + assemblyPatternBlock);
		}
		AssemblyPatternBlock noWildcardMask =
				PCAssemblerUtils.getNoWildcardMask(operandInfos, assemblyPatternBlock);
		if (PickledCanary.DEBUG) {
			System.err.println("noWildcardMask = " + noWildcardMask);
		}
		if (noWildcardMask == null) {
			return;
		}

		List<Integer> noWildcardMaskList = PCBytes.integerList(noWildcardMask.getMaskAll());

		// build data instruction for json
		// lookup step mask exists
		if (lookupStep.hasMask(noWildcardMaskList)) {
			Data data = lookupStep.getData(noWildcardMaskList);
			if (data instanceof LookupData lookupData) {
				// if InstructionEncoding does not exist, make one
				if (!lookupData.hasChoice(noWildcardMask.getValsAll())) {
					InstructionEncoding ie = new InstructionEncoding(noWildcardMask.getValsAll());
					lookupData.putChoice(noWildcardMask.getValsAll(), ie);
				}
				lookupStep.putData(noWildcardMaskList, lookupData);
			}
		}
		else {
			// no LookupData or InstructionEncoding -- make both
			InstructionEncoding ie = new InstructionEncoding(noWildcardMask.getValsAll());
			LookupData lookupData = new LookupData(noWildcardMask.getMaskAll());
			lookupData.putChoice(noWildcardMask.getValsAll(), ie);
			lookupStep.putData(noWildcardMaskList, lookupData);
		}

		for (WildOperandInfo assemblyOperandData : operandInfos) {
			if (assemblyOperandData.wildcard().compareTo(PCAssemblerUtils.WILDCARD) == 0) {
				continue;
			}

			List<Integer> wildcardMask =
					PCBytes.integerList(assemblyOperandData.location().getMaskAll());

			while (wildcardMask.size() < assemblyPatternBlock.length()) {
				wildcardMask.add(0);
			}

			// get key of table
			String tableKey = noWildcardMask + "_" + assemblyOperandData.wildcard();

			// It's not a scalar operand
			if (assemblyOperandData.choice() != null) {
				tables.addOperand(assemblyOperandData, assemblyPatternBlock, tableKey);
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
			if (data instanceof LookupData lookupData) {
				InstructionEncoding ie = lookupData.getChoice(noWildcardMask.getValsAll());
				if (!ie.matches(ot)) {
					ie.addOperand(ot);
				}

				// Only add the input context when required
				// TODO: Any scenario where condensing encodings affects local context association?
				if (ot instanceof ScalarOperandMeta sm) {
					if (sm.hasContext() && ie.getContext() == null) {
						System.err.println("Adding the context!!!");
						ie.addContext(convertContext(context));
					}
				}
			}
		}
	}

	/**
	 * Class to help convert context into form expected by the solver.
	 * Beats having to reimplement a ton of functions.
	 */
	static class ContextAdapter implements DisassemblerContextAdapter {
		private final RegisterValue context;

		public ContextAdapter(RegisterValue context) {
			this.context = context;
		}

		@Override
		public RegisterValue getRegisterValue(Register register) {
			return context.getRegisterValue(register);
		}
	}

	/**
	 * Convert the context from the pattern into form expected by the solver.
	 */
	private int[] convertContext(RegisterValue context) {
		// TODO: Slight hack
		// Just using ContextCache for conversion from RegisterValue -> int[]
		ContextCache temp = new ContextCache();
		temp.registerVariable(context.getRegister());

		int[] convert = new int[temp.getContextSize()];
		temp.getContext(new ContextAdapter(context), convert);

		return convert;
	}

	/**
	 * @return the {@link LookupStep} generated by this builder.
	 */
	public LookupStep buildLookupStep() {
		return lookupStep;
	}
}
