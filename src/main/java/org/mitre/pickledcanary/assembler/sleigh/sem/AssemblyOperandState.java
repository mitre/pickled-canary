/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.pickledcanary.assembler.sleigh.sem;

import java.util.*;
import java.util.stream.Stream;

import org.mitre.pickledcanary.assembler.sleigh.symbol.AssemblyNumericTerminal;
import org.mitre.pickledcanary.assembler.sleigh.symbol.AssemblyTerminal;
import org.mitre.pickledcanary.assembler.sleigh.util.DbgTimer.DbgCtx;

import ghidra.app.plugin.processors.sleigh.ConstructState;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;

/**
 * The state corresponding to a non-sub-table operand
 * 
 * <p>
 * This is roughly analogous to {@link ConstructState}, but for assembly. However, it also records
 * the value of the operand and the actual operand symbol whose value it specifies.
 */
public class AssemblyOperandState extends AbstractAssemblyState {
	protected final AssemblyTerminal terminal;
	protected final long value;
	protected final OperandSymbol opSym;

	/**
	 * Construct the state for a given operand and selected value
	 * 
	 * @param resolver the resolver
	 * @param path the path for diagnostics
	 * @param shift the (right) shift of this operand
	 * @param terminal the terminal that generated this state
	 * @param value the value of the operand
	 * @param opSym the operand symbol
	 */
	public AssemblyOperandState(AssemblyTreeResolver resolver,
			List<AssemblyConstructorSemantic> path, int shift, AssemblyTerminal terminal,
			long value, OperandSymbol opSym) {
		super(resolver, path, shift, opSym.getMinimumLength());
		this.terminal = terminal;
		this.value = value;
		this.opSym = opSym;
	}

	@Override
	public int computeHash() {
		return Objects.hash(getClass(), shift, value, opSym);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof AssemblyOperandState)) {
			return false;
		}
		AssemblyOperandState that = (AssemblyOperandState) obj;
		if (this.resolver != that.resolver) {
			return false;
		}
		if (this.shift != that.shift) {
			return false;
		}
		if (this.value != that.value) {
			return false;
		}
		if (!Objects.equals(this.opSym, that.opSym)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return terminal + "=" + value + "(0x" + Long.toHexString(value) + ")";
	}

	/**
	 * Compute the size in bits of this operand's value
	 * 
	 * <p>
	 * If this operand does not have a strict size, 0 is returned.
	 * 
	 * @return the size
	 */
	protected int computeBitsize() {
		if (!(terminal instanceof AssemblyNumericTerminal)) {
			return 0;
		}
		AssemblyNumericTerminal numeric = (AssemblyNumericTerminal) terminal;
		return numeric.getBitSize();
	}

	/**
	 * Solve the operand's defining expression set equal to the desired value
	 * 
	 * @return the resolved patterns, an error, or a backfill
	 */
	protected AssemblyResolution solveNumeric() {
		int bitsize = computeBitsize();
		PatternExpression symExp = opSym.getDefiningExpression();
		if (symExp == null) {
			symExp = opSym.getDefiningSymbol().getPatternExpression();
		}
		DBG.println("Equation: " + symExp + " = " + Long.toHexString(value));
		String desc = "Solution to " + opSym + " in " + Long.toHexString(value) + " = " + symExp;
		AssemblyResolution sol =
			AssemblyTreeResolver.solveOrBackfill(symExp, value, bitsize, resolver.vals, null, desc);
		DBG.println("Solution: " + sol);
		AssemblyResolution shifted = sol.shift(shift);
		DBG.println("Shifted: " + shifted);
		return shifted;
	}

	@Override
	protected Stream<AssemblyResolvedPatterns> resolve(AssemblyResolvedPatterns fromRight,
			Collection<AssemblyResolvedError> errors) {
		try (DbgCtx dc = DBG.start("Resolving " + terminal)) {
			AssemblyResolution sol = solveNumeric();
			if (sol.isError()) {
				errors.add((AssemblyResolvedError) sol);
				return Stream.of();
			}

			fromRight.operandData = fromRight.operandData.copy();

			// get the operand data structure of the operand we want to populate info with
			// find this structure using the code name (e.g. reg64 or simm32)
			AssemblyOperandData operandData = fromRight.operandData.findOperandData(terminal.getName());

			// when we populate backfills, we won't have the code name to find the correct
			// operand data to populate, so we use description of the AssemblyResolution
			// instead
			operandData.setDescription(sol.description);

			if (sol.isBackfill()) {
				AssemblyResolvedPatterns combined =
					fromRight.combine((AssemblyResolvedBackfill) sol);
				return Stream.of(combined.withRight(fromRight));
			}
			AssemblyResolution combined = fromRight.combine((AssemblyResolvedPatterns) sol);
			if (combined == null) {
				errors.add(
					AssemblyResolution.error("Pattern/operand conflict", "Resolving " + terminal));
				return Stream.of();
			}

			AssemblyResolvedPatterns solResolved = (AssemblyResolvedPatterns) sol;

			// populate operand data node with mask, value, shift, and expression for normal
			// operands this is similar to the code for backfill shifts for normal operands
			// in OperandValueSolver
			operandData.setMask(solResolved.ins.getMask());
			operandData.setVal(solResolved.ins.getVals());
			operandData.addByteShift(solResolved.ins.getOffset());
			PatternExpression symExp = opSym.getDefiningExpression();
			if (symExp == null) {
				symExp = opSym.getDefiningSymbol().getPatternExpression();
			}
			operandData.setExpression(symExp);

			AssemblyResolvedPatterns pats = (AssemblyResolvedPatterns) combined;
			// Do not take constructor from right
			return Stream.of(pats.withRight(fromRight).withConstructor(null));
		}
	}
}
