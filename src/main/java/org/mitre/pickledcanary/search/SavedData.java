
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.search;

import org.mitre.pickledcanary.patterngenerator.output.steps.ConcreteOperand;
import org.mitre.pickledcanary.patterngenerator.output.steps.ConcreteOperandAddress;

import java.util.HashMap;

public class SavedData {

	public int start = -1;
	public int end = -1;
	public final HashMap<String, ConcreteOperand> variables = new HashMap<>();
	public final HashMap<String, Long> labels = new HashMap<>();

	public SavedData() {

	}

	public SavedData(SavedData old) {
		this.start = old.start;
		this.end = old.end;
		this.variables.putAll(old.variables);
		this.labels.putAll(old.labels);
	}

	public SavedData(int start, int end) {
		this.start = start;
		this.end = end;
	}

	public String toString() {
		return "Saved(Start:" + this.start + ", End: " + this.end + ", variables: " + variables.toString()
				+ ", labels: " + labels.toString() + ")";
	}

	public boolean addOrFail(ConcreteOperand input) {
		if (input instanceof ConcreteOperandAddress) {
			Long v = ((ConcreteOperandAddress) input).getValueLong();

			Long value = this.labels.get(input.getVarId());
			if (value == null) {
				// This cast is safe b/c of the check previous
				this.labels.put(input.getVarId(), v);
				return true;

			}
			return value == (long) v;
		}
		ConcreteOperand value = this.variables.get(input.getVarId());
		if (value == null) {
			this.variables.put(input.getVarId(), input);
			return true;
		}
		return (value.equals(input));
	}

	public boolean addOrFail(String label, long input) {
		Long value = this.labels.get(label);
		if (value == null) {
			this.labels.put(label, input);
			return true;
		}
		return (value.equals(input));
	}
}
