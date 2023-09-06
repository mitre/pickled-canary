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
package org.mitre.pickledcanary.assembler.sleigh.expr;

import java.util.Map;
import java.util.Set;

import org.mitre.pickledcanary.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.expression.StartInstructionValue;

/**
 * "Solves" expression of {@code inst_start}
 * 
 * <p>
 * Works like the constant solver, but takes the value of {@code inst_start}, which is given by the
 * assembly address.
 */
public class StartInstructionValueSolver extends AbstractExpressionSolver<StartInstructionValue> {

	public StartInstructionValueSolver() {
		super(StartInstructionValue.class);
	}

	@Override
	public AssemblyResolution solve(StartInstructionValue iv, MaskedLong goal,
			Map<String, Long> vals, AssemblyResolvedPatterns cur, Set<SolverHint> hints,
			String description) {
		throw new AssertionError(
			"INTERNAL: Should never be asked to solve for " + AssemblyTreeResolver.INST_START);
	}

	@Override
	public MaskedLong getValue(StartInstructionValue iv, Map<String, Long> vals,
			AssemblyResolvedPatterns cur) {
		return MaskedLong.fromLong(vals.get(AssemblyTreeResolver.INST_START));
	}

	@Override
	public int getInstructionLength(StartInstructionValue exp) {
		return 0;
	}

	@Override
	public MaskedLong valueForResolution(StartInstructionValue exp, Map<String, Long> vals,
			AssemblyResolvedPatterns rc) {
		return MaskedLong.fromLong(vals.get(AssemblyTreeResolver.INST_START));
	}
}
