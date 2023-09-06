
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.search;

/**
 * A thread of execution in our VM.
 * <p>
 * Holds a program counter (pc) pointing at a step in our Pattern and a state
 * object holding the state we've gathered so far (e.g. match start address
 * and/or variable values [e.g. Q1=r0]).
 *
 */
public class Thread {

	public final int pc;
	public final SavedData saved;

	public Thread(int pc, SavedData saved) {
		this.pc = pc;
		this.saved = saved;
	}

	public String toString() {
		return "Thread(pc:" + this.pc + ", " + this.saved.toString() + ")";
	}

}
