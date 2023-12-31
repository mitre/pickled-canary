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

import java.util.*;

import org.mitre.pickledcanary.assembler.sleigh.grammars.AssemblyGrammar;
import org.mitre.pickledcanary.assembler.sleigh.tree.AssemblyParseToken;

/**
 * A terminal that accepts only a particular string
 */
public class AssemblyStringTerminal extends AssemblyTerminal {
	protected final String str;

	/**
	 * Construct a terminal that accepts only the given string
	 * 
	 * @param str the string to accept
	 */
	public AssemblyStringTerminal(String str) {
		super("\"" + str + "\"");
		this.str = str;
	}

	@Override
	public String toString() {
		return "\"" + str + "\"";
	}

	@Override
	public Collection<AssemblyParseToken> match(String buffer, int pos, AssemblyGrammar grammar,
			AssemblyNumericSymbols symbols) {
		if (buffer.regionMatches(pos, str, 0, str.length())) {
			return Collections.singleton(new AssemblyParseToken(grammar, this, str));
		}
		return Collections.emptySet();
	}
	
	@Override
	public Collection<AssemblyParseToken> matchAll(AssemblyGrammar grammar,
			AssemblyNumericSymbols symbols) {
		return Collections.singleton(new AssemblyParseToken(grammar, this, str));
	}

	@Override
	public Collection<String> getSuggestions(String got, AssemblyNumericSymbols symbols) {
		return Collections.singleton(str);
	}

	@Override
	public boolean takesOperandIndex() {
		return false;
	}
}
