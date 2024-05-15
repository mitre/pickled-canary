
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.search;

import java.util.LinkedList;

/**
 * A first-in-first-out queue of states to be processed for each step of the
 * binary (list of lists)
 *
 */
public class States {

	protected final LinkedList<LinkedList<Thread>> inner;
	protected final int startIdx;

	public States() {
		this.inner = new LinkedList<>();
		this.startIdx = 0;
	}

	public void add(int sp, Thread t) {
		int spIndex = sp - this.startIdx;
		LinkedList<Thread> v;
		try {
			v = this.inner.get(spIndex);
		} catch (IndexOutOfBoundsException e) {
			while (this.inner.size() <= spIndex) {
				this.inner.add(new LinkedList<>());
			}
			v = this.inner.get(spIndex);
		}
		v.push(t);
	}

	public Thread getNextThread(int sp) {
		try {
			LinkedList<Thread> l = this.inner.get(sp - this.startIdx);
			if (!l.isEmpty()) {
				return l.remove(0);
			}
		} catch (IndexOutOfBoundsException e) {
			return null;
		}
		return null;
	}
	// TODO: implement cleanup of old lists (e.g. remove them and increment
	// start_idx)
}
