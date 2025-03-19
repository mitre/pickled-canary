
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.search;

import org.mitre.pickledcanary.patterngenerator.output.steps.Step;
import org.mitre.pickledcanary.patterngenerator.output.steps.Jmp;
import org.mitre.pickledcanary.patterngenerator.output.steps.Label;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupAndCheckResult;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupStep;
import org.mitre.pickledcanary.patterngenerator.output.steps.MaskedByte;
import org.mitre.pickledcanary.patterngenerator.output.steps.Match;
import org.mitre.pickledcanary.patterngenerator.output.steps.SaveStart;
import org.mitre.pickledcanary.patterngenerator.output.steps.Split;
import org.mitre.pickledcanary.patterngenerator.output.steps.SplitMulti;
import org.mitre.pickledcanary.patterngenerator.output.steps.AnyByte;
import org.mitre.pickledcanary.patterngenerator.output.steps.AnyByteSequence;
import org.mitre.pickledcanary.patterngenerator.output.steps.Byte;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

/**
 * A modified pikevm supporting pickled canary patterns and their associated
 * complexity.
 * <p>
 * There's a reasonable chance you should probably use the VmSearch class (which
 * wraps this class) instead.
 *
 */
public class Pikevm {

	protected final PikevmStates states;
	protected final Pattern pattern;
	protected final MemBuffer input;
	protected final TaskMonitor monitor;
	protected final boolean doDotStar;
	protected int sp = 0;
	protected int spOfLastAddedThread = -1;
	protected Address max = null;

	public Pikevm(Pattern pattern, MemBuffer input, TaskMonitor monitor) {
		this.states = new PikevmStates();
		this.pattern = pattern;
		this.input = input;
		this.monitor = monitor;

		this.doDotStar = this.startsWithDotStar();
	}

	/**
	 * Set the max address that should be searched.
	 * 
	 * Implementation detail: Since we often process a "match" step one byte after the end of a
	 * match this function will add one to the given address before it's stored.
	 * 
	 * @param max
	 */
	public void setMaxAddress(Address max) {
		this.max = max.add(1);
	}

	private boolean startsWithDotStar() {
		boolean startsWithDotStar = true;
		Pattern dotStar = Pattern.getDotStar().append(Pattern.getSaveStart());
		int dotStartSize = dotStar.steps.size();
		if (pattern.steps.size() >= dotStartSize+1) {
			for (int i = 0; i < dotStartSize; i++) {
				if (!pattern.steps.get(i).equals(dotStar.steps.get(i))) {
					startsWithDotStar = false;
					break;
				}
			}
		}
		return startsWithDotStar;
	}

	/**
	 * Execute this pikevm with the parameters supplied on creation.
	 * 
	 * If called multiple times, subsequent calls will resume searching with the state left behind
	 * after the previous match (e.g. searching will continue as if the previously obtained match
	 * was not a match)
	 *
	 * @return
	 * @throws MemoryAccessException
	 */
	public SavedData run() {
		long startingMonitorValue = this.monitor.getProgress();

		if (!this.doDotStar && spOfLastAddedThread != sp) {
			this.addThread(sp, 0, new SavedData());
			spOfLastAddedThread = sp;
		}
		// This will throw an exception when it reaches the end
		while (true) {
			PikevmThread curPikevmThread = null;
			if (sp % 256 == 0 && this.monitor.isCancelled()) {
				return null;
			}
			
			if (sp % 0x1000 == 0) {
				monitor.setProgress(startingMonitorValue + sp);
			}

			if (this.doDotStar && spOfLastAddedThread != sp) {
				SavedData s = new SavedData();
				s.start = sp;
				curPikevmThread = new PikevmThread(4, s);
				spOfLastAddedThread = sp;
			}

			// bail when we've reached one past the end of our readable bytes.
			// We process one past the end here to allow hitting a match on the last byte.
			// Another possible option is to move Match to addThread and handle returning
			// from there upon match
			try {
				this.input.getByte(Math.max(0, sp - 1));
			} catch (MemoryAccessException e) {
				break;
			}

			if (this.max != null) {
				if (this.input.getAddress().add(sp).compareTo(this.max) > 0) {
					break;
				}
			}

			while (true) {
				if (curPikevmThread == null) {
					curPikevmThread = this.states.getNextThread(sp);
				}
				if (curPikevmThread == null) {
					break;
				}

				SavedData result;
				try {
					result = this.processThread(curPikevmThread);
				} catch (MemoryAccessException e) {
					curPikevmThread = null;
					continue;
				}
				if (result != null) {
					return result;
				}
				curPikevmThread = null;
			}
			curPikevmThread = null;
			sp += 1;
		}
		return null;
	}

	/**
	 * Add a thread of execution to be worked on later.
	 * <p>
	 * This pre-processes non-blocking steps to preserve match priority (e.g. this
	 * follows all splits and jmps and creates threads for all the destinations)
	 * 
	 * @param spNext
	 * @param pc
	 * @param saved
	 */
	private void addThread(int spNext, int pc, SavedData saved) {
		Step curStep = this.pattern.steps.get(pc);
		if (curStep instanceof Jmp jmp) {
			this.addThread(spNext, jmp.getDest(), saved);
		} else if (curStep instanceof Split split) {
			this.addThread(spNext, split.getDest1(), new SavedData(saved));
			this.addThread(spNext, split.getDest2(), saved);
		} else if (curStep instanceof SplitMulti splitMulti) {
			for (int dest : splitMulti.getDests()) {
				this.addThread(spNext, dest, new SavedData(saved));
			}
		} else if (curStep instanceof SaveStart) {
			saved.start = spNext;
			this.addThread(spNext, pc + 1, saved);
		} else if (curStep instanceof Label label) {
			SavedData newSavedData = new SavedData(saved);
			if (newSavedData.addOrFail(label.getValue(), input.getAddress().add(spNext).getUnsignedOffset())) {
				this.addThread(spNext, pc + 1, newSavedData);
			}
		} else {
			this.states.add(spNext, new PikevmThread(pc, saved));
		}
	}

	/**
	 * Process a thread with the given parameters, adding additional threads to
	 * <code>this.states</code> to be processed later if necessary.
	 * 
	 * @param pikevmThread
	 * @return A Result if a match is found, null otherwise.
	 * @throws MemoryAccessException
	 */
	private SavedData processThread(PikevmThread pikevmThread) throws MemoryAccessException {
		int pc = pikevmThread.pc();
		SavedData saved = pikevmThread.saved();
		Step curStep = this.pattern.steps.get(pc);
		if (curStep instanceof Byte byteStep) {
			if (this.input.getByte(sp) == (byte) byteStep.getValue()) {
				this.addThread(sp + 1, pc + 1, saved);
			}
			return null;
		} else if (curStep instanceof MaskedByte maskedByte) {
			byte maskedInput = (byte) (this.input.getByte(sp) & maskedByte.getMask());
			if (maskedInput == (byte) maskedByte.getValue()) {
				this.addThread(sp + 1, pc + 1, saved);
			}
			return null;
		} else if (curStep instanceof AnyByte) {
			this.addThread(sp + 1, pc + 1, saved);
			return null;
		} else if (curStep instanceof AnyByteSequence anyByteSequence) {
			for (int i = anyByteSequence.getMin(); i <= anyByteSequence.getMax(); i += anyByteSequence.getInterval()) {
				this.addThread(sp + i, pc + 1, saved);
			}
			return null;
		} else if (curStep instanceof LookupStep lookupStep) {
			for (LookupAndCheckResult result : lookupStep.doLookup(input, sp, this.pattern.tables, saved)) {
				this.addThread(sp + result.getSize(), pc + 1, result.getNewSaved());
			}
			return null;
		} else if (curStep instanceof Match) {
			saved.end = sp;
			return saved;
		}
		else if (curStep instanceof Jmp || curStep instanceof Split ||
			curStep instanceof SplitMulti || curStep instanceof SaveStart ||
			curStep instanceof Label) {
			// We should only hit this case on the FIRST step of a pattern (all others should be
			// handled by recursive calls in addThread)
			this.addThread(sp, pc, saved);
			return null;
		}
		throw new UnsupportedOperationException("Shouldn't Get here! Is there an other opcode which needs to be implemented?");
	}
}
