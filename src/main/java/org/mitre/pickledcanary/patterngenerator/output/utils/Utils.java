
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.utils;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;

public class Utils {
	private Utils() {}

	/**
	 * Get key for the tables. Key consists of the instruction's value as a binary
	 * string with wildcard bits replaced with x's. Mask and Value should be same
	 * length
	 * 
	 * @param mask Binary string mask of wildcard
	 * @param val  Binary string value of instruction
	 * @return key where binary string value has wildcard bits replaced by x's
	 */
	public static String maskToX(String mask, String val) {
		if (mask.length() != val.length()) {
			throw new IllegalArgumentException(
					"mask and value must be the same length! " +
					"Mask: " + mask + " Len: " + mask.length() + " Val: " + val + " Len: " + val.length());
		}

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < mask.length(); i++) {
			if (mask.charAt(i) == '0') {
				// bit not part of wildcard
				sb.append(val.charAt(i));
			} else {
				// bit is part of wildcard
				sb.append('x');
			}
		}
		return sb.toString();
	}

	/**
	 * Reverse order of byte array. Used to convert from big to little endian and
	 * vice versa.
	 * 
	 * @param arr the byte array to reverse
	 * @return a new reversed byte array
	 */
	public static byte[] reverse(byte[] arr) {
		byte[] reversed = new byte[arr.length];
		for (int i = 0; i < arr.length; i++) {
			reversed[i] = arr[arr.length - i - 1];
		}
		return reversed;
	}

	/**
	 * Get decimal mask and decimal representation of wildcarded operand. Used for
	 * the map from operand to mask and value in the tables. Decimal values are 8
	 * bits. Masks or values that use more than 8 bits will use another byte.
	 * 
	 * @param mask Byte mask of the operand
	 * @param val  Byte value of the instruction
	 * @return decimal mask and decimal value of the wildcarded operand
	 */
	public static List<List<Integer>> binToDecMaskVal(byte[] mask, byte[] val) {
		// convert byte[] to BitSet
		BitSet maskBS = BitSet.valueOf(reverse(mask));
		BitSet valBS = BitSet.valueOf(reverse(val));

		// strip off the leading and trailing 0 bits
		for (int i = 0; i < maskBS.length(); i++) {
			if (maskBS.get(i)) {
				valBS = valBS.get(i, maskBS.length());
				maskBS = maskBS.get(i, maskBS.length());
				break;
			}
		}
		valBS.and(maskBS);

		// convert from BitSet back to byte[]
		List<Integer> masks = new ArrayList<>();
		List<Integer> vals = new ArrayList<>();
		byte[] maskOut = reverse(maskBS.toByteArray());
		byte[] valOut = reverse(valBS.toByteArray());
		for (byte m : maskOut) {
			masks.add(m & 0xFF);
		}

		// add any necessary leading 0s to value
		for (int i = valOut.length; i < maskOut.length; i++) {
			vals.add(0);
		}
		for (byte v : valOut) {
			vals.add(v & 0xFF);
		}

		// masks and values shouldn't be empty lists
		if (masks.isEmpty()) {
			masks.add(0);
		}
		if (vals.isEmpty()) {
			vals.add(0);
		}

		List<List<Integer>> outMaskVal = new ArrayList<>();
		outMaskVal.add(masks);
		outMaskVal.add(vals);

		return outMaskVal;
	}

//	/**
//	 * Use the disassembler to check masks and values of opcode and top-level operands of an instruction.
//	 * Prints result to console.
//	 * 
//	 * @param currentProgram Ghidra program open that uses the same architecture as the instruction to debug
//	 * @param currentAddress the address where the cursor is located in the Ghidra program
//	 * @param assembler assembler that can process the instruction to debug
//	 * @param instructionBytes bytes of the instruction to debug
//	 */
//	public static void assemblerDebug(Program currentProgram, Address currentAddress, Assembler assembler,
//			byte[] instructionBytes) {
//		// write the instruction to where the cursor is
//		try {
//			assembler.patchProgram(instructionBytes, currentAddress);
//		} catch (MemoryAccessException e) {
//			e.printStackTrace();
//			throw new RuntimeException("Could not write assembly instruction to program");
//		}
//
//		Instruction instruction = currentProgram.getListing().getInstructionAt(currentAddress);
//		while (instruction == null) {
//			instruction = currentProgram.getListing().getInstructionAfter(currentAddress);
//			currentAddress = instruction.getAddress();
//			System.out.println("WARNING: Could not process instruction. Moving address to " + currentAddress
//					+ " and trying again.");
//		}
//
//		// used for getting the different parts of the instruction
//		final SleighDebugLogger logger = new SleighDebugLogger(currentProgram, currentAddress, SleighDebugMode.VERBOSE);
//
//		for (int i = -1; i < logger.getNumOperands(); i++) {
//			String asciiRep; // assembly representation
//			if (i == -1) { // get mnemonic
//				asciiRep = instruction.getMnemonicString();
//			} else { // get operand string
//				asciiRep = instruction.getDefaultOperandRepresentation(i);
//			}
//
//			// mask which tells which bits are relevant to mnemonic/operand
//			String maskStr = logger.getFormattedInstructionMask(i);
//			// binary representation of the mnemonic/operand
//			String value = logger.getFormattedMaskedValue(i);
//			System.out.println(maskStr + " " + asciiRep + " Mask");
//			System.out.println(value + " " + asciiRep + " Value");
//		}
//	}
}
