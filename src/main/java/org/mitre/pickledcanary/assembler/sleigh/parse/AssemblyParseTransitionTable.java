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
package org.mitre.pickledcanary.assembler.sleigh.parse;

import java.util.Map;
import java.util.TreeMap;
import java.util.function.Consumer;

import org.mitre.pickledcanary.assembler.sleigh.symbol.AssemblySymbol;
import org.mitre.pickledcanary.assembler.sleigh.util.TableEntry;
import org.mitre.pickledcanary.assembler.sleigh.util.TableEntryKey;

/**
 * The transition table defining an LR(0) parsing machine
 */
public class AssemblyParseTransitionTable {
	// a map for the (sparse) table
	private final Map<TableEntryKey, Integer> map = new TreeMap<>();

	/**
	 * Put an entry into the state machine
	 * 
	 * <p>
	 * <b>NOTE:</b> Generally, if this returns non-null, something is probably wrong with your LR(0)
	 * machine generator
	 * 
	 * @param fromState the source state
	 * @param next the symbol that is matched
	 * @param newState the destination state
	 * @return the previous value for newState
	 */
	public Integer put(int fromState, AssemblySymbol next, int newState) {
		return map.put(new TableEntryKey(fromState, next), newState);
	}

	/**
	 * Get an entry from the state machine
	 * 
	 * @param fromState the source state
	 * @param next the symbol that has been matched
	 * @return the destination state
	 */
	public Integer get(int fromState, AssemblySymbol next) {
		return map.get(new TableEntryKey(fromState, next));
	}

	/**
	 * Traverse every entry in the table, invoking {@link Consumer#accept(Object)} on each
	 * 
	 * @param consumer the callback
	 */
	public void forEach(Consumer<TableEntry<Integer>> consumer) {
		for (Map.Entry<TableEntryKey, Integer> ent : map.entrySet()) {
			consumer.accept(
				new TableEntry<>(ent.getKey().getState(), ent.getKey().getSym(), ent.getValue()));
		}
	}
}
