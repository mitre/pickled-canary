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

import java.util.Collection;

import org.mitre.pickledcanary.assembler.sleigh.grammars.AssemblyGrammar;
import org.mitre.pickledcanary.assembler.sleigh.tree.AssemblyParseToken;

/**
 * The type of terminal for an assembly grammar
 * 
 * <p>
 * Unlike classical parsing, each terminal provides its own tokenizer. If multiple tokenizers yield
 * a token, the parser branches, possibly creating multiple, ambiguous trees.
 * 
 * @see AssemblyGrammar
 */
public abstract class AssemblyTerminal extends AssemblySymbol {
	/**
	 * Construct a terminal having the give name
	 * 
	 * @param name
	 */
	public AssemblyTerminal(String name) {
		super(name);
	}

	/**
	 * Attempt to match a token from the input buffer starting at a given position
	 * 
	 * @param buffer the input buffer
	 * @param pos the cursor position in the buffer
	 * @param grammar the grammar containing this terminal
	 * @param symbols symbols from the program, suitable for use as numeric terminals
	 * @return the matched token, or null
	 */
	public abstract Collection<? extends AssemblyParseToken> match(String buffer, int pos,
			AssemblyGrammar grammar, AssemblyNumericSymbols symbols);
	
	/**
	 * Just like "match" but always claims that "buffer" (which isn't even
	 * passed to this function) is a match with this AssemblyTerminal at pos
	 * (which, again, isn't even passed)
	 * @param grammar the grammar containing this terminal
	 * @param labels the program labels, if applicable
	 * @return the matched token, or null
	 */
	public abstract Collection<? extends AssemblyParseToken> matchAll(AssemblyGrammar grammar, AssemblyNumericSymbols labels);

	/**
	 * Provide a collection of strings that this terminal would have accepted
	 * 
	 * @param got the remaining contents of the input buffer
	 * @param symbols the program symbols, if applicable
	 * @return a, possibly empty, collection of suggestions
	 */
	public abstract Collection<String> getSuggestions(String got, AssemblyNumericSymbols symbols);
}
