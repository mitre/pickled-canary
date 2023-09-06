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
package org.mitre.pickledcanary.assembler.sleigh.grammars;

import java.util.*;

import org.mitre.pickledcanary.assembler.sleigh.sem.AssemblyConstructorSemantic;
import org.mitre.pickledcanary.assembler.sleigh.symbol.AssemblyNonTerminal;

import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;

/**
 * Defines a context free grammar, used to parse mnemonic assembly instructions
 * 
 * <p>
 * This stores the CFG and the associated semantics for each production. It also has mechanisms for
 * tracking "purely recursive" productions. These are productions of the form I =&gt; I, and they
 * necessarily create ambiguity. Thus, when constructing a parser, it is useful to identify them
 * early.
 */
public class AssemblyGrammar
		extends AbstractAssemblyGrammar<AssemblyNonTerminal, AssemblyProduction> {
	// a nested map of semantics by production, by constructor
	protected final Map<AssemblyProduction, Map<Constructor, AssemblyConstructorSemantic>> semanticsByProduction =
		new TreeMap<>();
	protected final Map<Constructor, AssemblyConstructorSemantic> semanticsByConstructor =
		new HashMap<>();
	// a map of purely recursive, e.g., I => I, productions by name of LHS
	protected final Map<String, AssemblyProduction> pureRecursive = new TreeMap<>();

	@Override
	protected AssemblyProduction newProduction(AssemblyNonTerminal lhs,
			AssemblySentential<AssemblyNonTerminal> rhs) {
		return new AssemblyProduction(lhs, rhs);
	}

	@Override
	public void addProduction(AssemblyProduction prod) {
		if (isPureRecursive(prod)) {
			pureRecursive.put(prod.getLHS().getName(), prod);
		}
		else {
			super.addProduction(prod);
		}
	}

	/**
	 * Add a production associated with a SLEIGH constructor semantic
	 * 
	 * @param lhs the left-hand side
	 * @param rhs the right-hand side
	 * @param pattern the pattern associated with the constructor
	 * @param cons the SLEIGH constructor
	 * @param indices the indices of RHS non-terminals that represent an operand in the constructor
	 */
	public void addProduction(AssemblyNonTerminal lhs, AssemblySentential<AssemblyNonTerminal> rhs,
			DisjointPattern pattern, Constructor cons, List<Integer> indices) {
		AssemblyProduction prod = newProduction(lhs, rhs);
		addProduction(prod);
		Map<Constructor, AssemblyConstructorSemantic> map =
			semanticsByProduction.computeIfAbsent(prod, p -> new TreeMap<>());
		AssemblyConstructorSemantic sem =
			map.computeIfAbsent(cons, c -> new AssemblyConstructorSemantic(cons, indices));
		if (!indices.equals(sem.getOperandIndices())) {
			throw new IllegalStateException(
				"Productions of the same constructor must have same operand indices");
		}
		semanticsByConstructor.put(cons, sem);

		sem.addPattern(pattern);
	}

	/**
	 * Get the semantics associated with a given production
	 * 
	 * @param prod the production
	 * @return all semantics associated with the given production
	 */
	public Collection<AssemblyConstructorSemantic> getSemantics(AssemblyProduction prod) {
		return Collections.unmodifiableCollection(
			semanticsByProduction.computeIfAbsent(prod, p -> new TreeMap<>()).values());
	}

	public AssemblyConstructorSemantic getSemantic(Constructor cons) {
		return semanticsByConstructor.get(cons);
	}

	@Override
	public void combine(AbstractAssemblyGrammar<AssemblyNonTerminal, AssemblyProduction> that) {
		super.combine(that);
		if (that instanceof AssemblyGrammar) {
			AssemblyGrammar ag = (AssemblyGrammar) that;
			this.semanticsByProduction.putAll(ag.semanticsByProduction);
			this.semanticsByConstructor.putAll(ag.semanticsByConstructor);
			this.pureRecursive.putAll(ag.pureRecursive);
		}
	}

	/**
	 * Get all productions in the grammar that are purely recursive
	 * 
	 * @return
	 */
	public Collection<AssemblyProduction> getPureRecursive() {
		return pureRecursive.values();
	}

	/**
	 * Obtain, if present, the purely recursive production having the given LHS
	 * 
	 * @param lhs the left-hand side
	 * @return the desired production, or null
	 */
	public AssemblyProduction getPureRecursion(AssemblyNonTerminal lhs) {
		return pureRecursive.get(lhs.getName());
	}
}
