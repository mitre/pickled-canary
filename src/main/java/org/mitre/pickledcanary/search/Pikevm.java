
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

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

	protected final States states;
	protected final Pattern pattern;
	protected final MemBuffer input;
	protected final TaskMonitor monitor;

	public Pikevm(Pattern pattern, MemBuffer input, TaskMonitor monitor) {
		this.states = new States();
		this.pattern = pattern;
		this.input = input;
		this.monitor = monitor;
	}

	/**
	 * Add a thread of execution to be worked on later.
	 * <p>
	 * This pre-processes non-blocking steps to preserve match priority (e.g. this
	 * follows all splits and jmps and creates threads for all the destinations)
	 * 
	 * @param sp
	 * @param pc
	 * @param saved
	 */
	private void addThread(int sp, int pc, SavedData saved) {
		Step curStep = this.pattern.steps.get(pc);
		if (curStep instanceof Jmp jmp) {
			this.addThread(sp, jmp.getDest(), saved);
		} else if (curStep instanceof Split split) {
			this.addThread(sp, split.getDest1(), new SavedData(saved));
			this.addThread(sp, split.getDest2(), saved);
		} else if (curStep instanceof SplitMulti splitMulti) {
			for (int dest : splitMulti.getDests()) {
				this.addThread(sp, dest, new SavedData(saved));
			}
		} else if (curStep instanceof SaveStart) {
			saved.start = sp;
			this.addThread(sp, pc + 1, saved);
		} else if (curStep instanceof Label label) {
			SavedData newSavedData = new SavedData(saved);
			if (newSavedData.addOrFail(label.getValue(), input.getAddress().add(sp).getUnsignedOffset())) {
				this.addThread(sp, pc + 1, newSavedData);
			}
		} else {
			this.states.add(sp, new Thread(pc, saved));
		}
	}

	/**
	 * Process a thread with the given parameters, adding additional threads to
	 * <code>this.states</code> to be processed later if necessary.
	 * 
	 * @param sp
	 * @param pc
	 * @param saved
	 * @return A Result if a match is found, null otherwise.
	 * @throws MemoryAccessException
	 */
	private SavedData processThread(int sp, int pc, SavedData saved) throws MemoryAccessException {
		while (true) {
			Step curStep = this.pattern.steps.get(pc);
			if (curStep instanceof Byte) {
				if (this.input.getByte(sp) == (byte) ((Byte) curStep).getValue()) {
					this.addThread(sp + 1, pc + 1, saved);
				}
				break;
			} else if (curStep instanceof MaskedByte maskedByte) {
				byte maskedInput = (byte) (this.input.getByte(sp) & maskedByte.getMask());
				if (maskedInput == (byte) maskedByte.getValue()) {
					this.addThread(sp + 1, pc + 1, saved);
				}
				break;
			} else if (curStep instanceof AnyByte) {
				this.addThread(sp + 1, pc + 1, saved);
				break;
			} else if (curStep instanceof AnyByteSequence anyByteSequence) {
				for (int i = anyByteSequence.getMin(); i <= anyByteSequence.getMax(); i += anyByteSequence.getInterval()) {
					this.addThread(sp + i, pc + 1, saved);
				}
				break;
			} else if (curStep instanceof LookupStep lookupStep) {
				for (LookupAndCheckResult result : lookupStep.doLookup(input, sp, this.pattern.tables, saved)) {
					this.addThread(sp + result.getSize(), pc + 1, result.getNewSaved());
				}
				break;
			} else if (curStep instanceof Match) {
				saved.end = sp;
				return saved;
			}
			throw new RuntimeException("Shouldn't Get here! Is there an other opcode which needs to be implemented?");
		}
		return null;
	}

	/**
	 * Execute this pikevm with the parameters supplied on creation.
	 * 
	 * @return
	 * @throws MemoryAccessException
	 */
	public SavedData run() {
		int sp = 0;
		this.addThread(sp, 0, new SavedData());

		// This will throw an exception when it reaches the end
		while (true) {

			if (sp % 256 == 0 && this.monitor.isCancelled()) {
				return null;
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

			while (true) {
				Thread curThread = this.states.getNextThread(sp);
				if (curThread == null) {
					break;
				}

				SavedData result;
				try {
					result = this.processThread(sp, curThread.pc, curThread.saved);
				} catch (MemoryAccessException e) {
					continue;
				}
				if (result != null) {
					return result;
				}
			}
			sp += 1;
		}
		return null;
	}
}
