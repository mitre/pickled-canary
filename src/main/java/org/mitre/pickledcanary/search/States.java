
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
	protected final int start_idx;

	public States() {
		this.inner = new LinkedList<>();
		this.start_idx = 0;
	}

	public void add(int sp, Thread t) {
		int sp_index = sp - this.start_idx;
		LinkedList<Thread> v;
		try {
			v = this.inner.get(sp_index);
		} catch (IndexOutOfBoundsException e) {
			while (this.inner.size() <= sp_index) {
				this.inner.add(new LinkedList<>());
			}
			v = this.inner.get(sp_index);
		}
		v.push(t);
	}

	public Thread get_next_thread(int sp) {
		try {
			LinkedList<Thread> l = this.inner.get(sp - this.start_idx);
			if (l.size() > 0) {
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
