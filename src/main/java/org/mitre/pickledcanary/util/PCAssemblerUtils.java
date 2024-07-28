// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.util;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.asm.wild.WildOperandInfo;

import java.util.Collection;
import java.util.HashMap;

public class PCAssemblerUtils {
	public static final String WILDCARD = "*";

	private PCAssemblerUtils() {
	}

	public static AssemblyPatternBlock getNoWildcardMask(Collection<WildOperandInfo> operandInfos,
			AssemblyPatternBlock assemblyPatternBlock) {
		AssemblyPatternBlock result = assemblyPatternBlock.copy();

		// In some cases (e.g. "SHRD EAX,EBX,`Q1[..]`" in x86 32 bit) the instruction
		// returned by getInstruction is shorter than the location mask of some of that
		// instruction's operands. This block checks if that's the case and if so,
		// lengthens the instruction to fit its operands.
		int maxOperandLocationLength = operandInfos
				.stream()
				.map(x -> x.location().getMaskAll().length)
				.max(Integer::compare)
				.orElse(0);

		if (result.getMaskAll().length < maxOperandLocationLength) {
			result = assemblyPatternBlock
					.combine(AssemblyPatternBlock.fromLength(maxOperandLocationLength));
		}

		HashMap<String, Object> operandChoices = new HashMap<>();
		for (WildOperandInfo info : operandInfos) {
			// remove masks of wildcards from the full instruction
			result = result.maskOut(info.location());

			// Just skip over instructions which have the same wildcard twice but with
			// different choices
			if (operandChoices.containsKey(info.wildcard())) {
				if (operandChoices.get(info.wildcard()) != info.choice()) {
					return null;
				}
			}
			else {
				operandChoices.put(info.wildcard(), info.choice());
			}
		}
		return result;
	}
}
