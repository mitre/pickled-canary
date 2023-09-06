
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import org.mitre.pickledcanary.search.SavedData;

public class LookupAndCheckResult {
	private final int size;
	private final SavedData saved;

	public LookupAndCheckResult(int size, SavedData saved) {
		this.size = size;
		this.saved = saved;
	}

	public int getSize() {
		return this.size;
	}

	public SavedData getNewSaved() {
		return this.saved;
	}

	public String toString() {
		return "LookupAndCheckResult(size: " + this.size + ", saved: " + this.saved.toString() + ")";
	}
}
