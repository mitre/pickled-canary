package org.mitre.pickledcanary.util;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.asm.wild.WildOperandInfo;
import ghidra.asm.wild.sem.WildAssemblyResolvedPatterns;
import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.patterngenerator.output.steps.*;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

public class PCAssemblerUtils {
    private PCAssemblerUtils() {}

    private static final String WILDCARD = "*";

    /**
     * Add the passed assembly patterns to
     * @param pats
     * @param tables
     * @param lookupStep
     */
    public static void addAssemblyPatternToStep(WildAssemblyResolvedPatterns pats, AllLookupTables tables, LookupStep lookupStep) {
        // TODO: not an ideal place as 2/3 of the inputs get modified
        AssemblyPatternBlock assemblyPatternBlock = pats.getInstruction();
        Set<WildOperandInfo> operandInfos = pats.getOperandInfo();

        if (PickledCanary.DEBUG) {
            System.err.println("assemblyPatternBlock = " + assemblyPatternBlock);
        }
        AssemblyPatternBlock noWildcardMask = getNoWildcardMask(operandInfos, assemblyPatternBlock);
        if (PickledCanary.DEBUG) {
            System.err.println("noWildcardMask = " + noWildcardMask);
        }
        if (noWildcardMask == null) return;

        List<Integer> noWildcardMaskList = PCBytes.integerList(noWildcardMask.getMaskAll());
        List<Integer> noWildcardValList = PCBytes.integerList(noWildcardMask.getValsAll());

        // build data instruction for json
        // lookup step mask exists
        if (lookupStep.hasMask(noWildcardMaskList)) {
            Data data = lookupStep.getData(noWildcardMaskList);
            if (data instanceof LookupData lookupData) {
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

        for (WildOperandInfo assemblyOperandData : operandInfos) {
            if (assemblyOperandData.wildcard().compareTo(WILDCARD) == 0) {
                continue;
            }

            List<Integer> wildcardMask =
                    PCBytes.integerList(assemblyOperandData.location().getMaskAll());

            while (wildcardMask.size() < assemblyPatternBlock.length()) {
                wildcardMask.add(0);
            }

            // get key of table
            String tableKey = noWildcardMask + "_0";

            // It's not a scalar operand
            if (assemblyOperandData.choice() != null) {
                tables.addOperand(assemblyOperandData, assemblyPatternBlock, tableKey);
            }

            // add operand to json
            OperandMeta ot;
            if (assemblyOperandData.choice() == null) {
                ot = new ScalarOperandMeta(wildcardMask, assemblyOperandData.wildcard(),
                        assemblyOperandData.expression());
            } else {
                ot = new FieldOperandMeta(wildcardMask, tableKey,
                        assemblyOperandData.wildcard());
            }
            Data data = lookupStep.getData(noWildcardMaskList);
            if (data instanceof LookupData lookupData) {
                InstructionEncoding ie = lookupData.getChoice(noWildcardValList);
                if (!ie.matches(ot)) {
                    ie.addOperand(ot);
                }
            }
        }
    }

    private static AssemblyPatternBlock getNoWildcardMask(Collection<WildOperandInfo> operandInfos, AssemblyPatternBlock assemblyPatternBlock) {
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
