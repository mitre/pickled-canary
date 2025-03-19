
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.search;

import java.util.HashMap;
import java.util.Map;

import org.mitre.pickledcanary.patterngenerator.output.steps.ConcreteOperand;

import static java.util.stream.Collectors.joining;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;

/**
 * This is very similar to SavedData, but the values in this class have been
 * converted to addresses.
 */
public record SavedDataAddresses(Address start, Address end, Map<String, ConcreteOperand> variables, Map<String, Address> labels) {

	/**
	 * Converts the given saved by adding base to the start and end values.
	 * <p>
	 * For example, if a match was saved in a SavedData at offset 7 and the base was
	 * 0x80000000, then the resulting SavedDataAddresses returned here has a start
	 * of 0x80000007
	 * 
	 * @param saved
	 * @param baseIn
	 */
	public SavedDataAddresses(SavedData saved, Address baseIn) {
		this(baseIn.add(saved.start), baseIn.add(saved.end), saved.variables, new HashMap<>());

		// Convert labels to Addresses
		Address base = baseIn.getNewAddress(0);
		for (Map.Entry<String, Long> x : saved.labels.entrySet()) {
			Address out;
			try {
				out = base.add(x.getValue());
			} catch (AddressOutOfBoundsException e) {
				System.out.println("Got an out of bounds trying to do: " + base.toString() + " + " + x.getValue());
				out = Address.NO_ADDRESS;
			}
			this.labels.put(x.getKey(), out);
		}
	}

	public Address getStart() {
		return start;
	}

	public Address getEnd() {
		return end;
	}

	public String getVarsString() {
		return this.variables.entrySet().stream().map(e -> e.getKey() + ":" + e.getValue().getValue())
				.collect(joining(", "));
	}

	public String getLabelsString() {
		return this.labels.entrySet().stream().map(e -> e.getKey() + ":" + e.getValue().toString())
				.collect(joining(", "));
	}
}
