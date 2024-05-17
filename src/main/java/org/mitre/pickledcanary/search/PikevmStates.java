
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.search;

import java.util.*;

/**
 * A first-in-first-out queue of states to be processed for each step of the
 * binary (list of lists)
 *
 */
public class PikevmStates {

	private final List<Deque<PikevmThread>> inner;
	private final int startIdx;

	public PikevmStates() {
		this.inner = new ArrayList<>();
		this.startIdx = 0;
	}

	/**
	 * Add a thread to a given stack level. If the stack level does not exist it will be created.
	 * @param sp the stack level
	 * @param t the thread to add
	 */
	public void add(int sp, PikevmThread t) {
		int spIndex = sp - this.startIdx;
		while (spIndex >= this.inner.size()) {
			this.inner.add(new ArrayDeque<>());
		}
		this.inner.get(spIndex).push(t);
	}

	/**
	 * Get the next thread from a given stack level, if it exists.
	 * @param sp the stack level
	 * @return the next thread in the queue for that stack level, if it exists.
	 */
	public PikevmThread getNextThread(int sp) {
		int spIndex = sp - this.startIdx;
		if (spIndex >= this.inner.size()) {
			return null;
		}
		return this.inner.get(spIndex).pollLast();
	}

	// TODO: implement cleanup of old lists (e.g. remove them and increment
	// start_idx)
}
