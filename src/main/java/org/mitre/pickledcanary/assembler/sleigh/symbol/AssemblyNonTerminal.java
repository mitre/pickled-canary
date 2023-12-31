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
package org.mitre.pickledcanary.assembler.sleigh.symbol;

import org.mitre.pickledcanary.assembler.sleigh.grammars.AssemblyGrammar;

/**
 * The type of non-terminal for an assembly grammar
 * 
 * @see AssemblyGrammar
 */
public class AssemblyNonTerminal extends AssemblySymbol {
	/**
	 * Construct a non-terminal having the given name
	 * 
	 * @param name the name
	 */
	public AssemblyNonTerminal(String name) {
		super(name);
	}

	@Override
	public String toString() {
		return "[" + name + "]";
	}
}
