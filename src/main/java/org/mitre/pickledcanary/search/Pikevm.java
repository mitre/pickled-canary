
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
	private void add_thread(int sp, int pc, SavedData saved) {
		Step cur_step = this.pattern.steps.get(pc);
		if (cur_step instanceof Jmp) {
			this.add_thread(sp, ((Jmp) cur_step).getDest(), saved);
		} else if (cur_step instanceof Split) {
			this.add_thread(sp, ((Split) cur_step).getDest1(), new SavedData(saved));
			this.add_thread(sp, ((Split) cur_step).getDest2(), saved);
		} else if (cur_step instanceof SplitMulti) {
			for (int dest : ((SplitMulti) cur_step).getDests()) {
				this.add_thread(sp, dest, new SavedData(saved));
			}
		} else if (cur_step instanceof SaveStart) {
			saved.start = sp;
			this.add_thread(sp, pc + 1, saved);
		} else if (cur_step instanceof Label) {
			SavedData newSavedData = new SavedData(saved);
			if (newSavedData.addOrFail(((Label) cur_step).getValue(), input.getAddress().add(sp).getUnsignedOffset())) {
				this.add_thread(sp, pc + 1, newSavedData);
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
	private SavedData process_thread(int sp, int pc, SavedData saved) throws MemoryAccessException {
		while (true) {
			Step cur_step = this.pattern.steps.get(pc);
			if (cur_step instanceof Byte) {
				if (this.input.getByte(sp) == (byte) ((Byte) cur_step).getValue()) {
					this.add_thread(sp + 1, pc + 1, saved);
				}
				break;
			} else if (cur_step instanceof MaskedByte) {
				MaskedByte x = ((MaskedByte) cur_step);
				byte masked_input = (byte) (this.input.getByte(sp) & x.getMask());
				if (masked_input == (byte) x.getValue()) {
					this.add_thread(sp + 1, pc + 1, saved);
				}
				break;
			} else if (cur_step instanceof AnyByte) {
				this.add_thread(sp + 1, pc + 1, saved);
				break;
			} else if (cur_step instanceof AnyByteSequence) {
				AnyByteSequence x = (AnyByteSequence) cur_step;
				for (int i = x.getMin(); i <= x.getMax(); i += x.getInterval()) {
					this.add_thread(sp + i, pc + 1, saved);
				}
				break;
			} else if (cur_step instanceof LookupStep) {

				LookupStep x = (LookupStep) cur_step;
				for (LookupAndCheckResult result : x.doLookup(input, sp, this.pattern.tables, saved)) {
					this.add_thread(sp + result.getSize(), pc + 1, result.getNewSaved());

				}
				break;
			} else if (cur_step instanceof Match) {
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
		this.add_thread(sp, 0, new SavedData());

		// This will throw an exception when it reaches the end
		while (true) {

			if (sp % 256 == 0 && this.monitor.isCancelled()) {
				return null;
			}

			// bail when we've reached one past the end of our readable bytes.
			// We process one past the end here to allow hitting a match on the last byte.
			// Another possible option is to move Match to add_thread and handle returning
			// from there upon match
			try {
				this.input.getByte(Math.max(0, sp - 1));
			} catch (MemoryAccessException e) {
				break;
			}

			while (true) {
				Thread cur_thread = this.states.get_next_thread(sp);
				if (cur_thread == null) {
					break;
				}

				SavedData result;
				try {
					result = this.process_thread(sp, cur_thread.pc, cur_thread.saved);
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
