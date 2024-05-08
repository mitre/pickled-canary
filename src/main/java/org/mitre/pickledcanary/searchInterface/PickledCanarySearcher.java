
/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

/*
 * Based on Ghidra's sample SampleSearcher.
 */

// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.searchInterface;

import java.awt.event.TextEvent;
import java.awt.event.TextListener;
import java.util.ArrayList;

import org.json.JSONObject;
import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.patterngenerator.PCVisitor;
import org.mitre.pickledcanary.search.Pattern;
import org.mitre.pickledcanary.search.SavedDataAddresses;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;

public class PickledCanarySearcher {

	final static public String CompilingString = "Compiling Pattern...";
	final static public String NotCompiledString = "Compile pattern first!";

	private final Program program;
	private final Address currentAddress;
	private String query;
	private boolean removeDebugFlag;
	private PCVisitor visitor;
	private final ArrayList<TextListener> listeners = new ArrayList<>();
	private String compiledPattern = NotCompiledString; // keeps track of if the pattern is compiling or not

	public PickledCanarySearcher(Program program, Address currentAddress, String query) {
		this.program = program;
		this.currentAddress = currentAddress;
		this.query = query;
		this.removeDebugFlag = false;
	}

	private void notifyListeners() {
		for (TextListener listener : this.listeners) {
			listener.textValueChanged(new TextEvent(this, 900));
		}
	}

	public void search(Accumulator<SavedDataAddresses> accumulator, TaskMonitor monitor) {

		// Set our message to say that we're compiling... and tell everyone who cares
		this.compiledPattern = PickledCanarySearcher.CompilingString;
		this.notifyListeners();

		// Parse and compile our pattern to json (and tell everyone who cares)
		this.visitor = PickledCanary.createAndRunVisitor(monitor, query, program, currentAddress);

		JSONObject o = this.visitor.getJSONObject(!removeDebugFlag);

		this.compiledPattern = o.toString(4);
		this.notifyListeners();

		// Now assemble our pattern into a Java-runnable pattern
		Pattern patternCompiled = this.visitor.getPattern().wrap();

		// Run the pattern
		PickledCanary.runAll(monitor, program, patternCompiled, accumulator);

		monitor.setIndeterminate(false);
	}

	public void setQuery(String query) {
		this.query = query;
		this.compiledPattern = NotCompiledString;
	}

	public Program getProgram() {
		return program;
	}

	/**
	 * This should only be used to set error messages
	 * 
	 * @param msg
	 */
	public void setCompiledPattern(String msg) {
		this.compiledPattern = msg;
	}

	public String getCompiledPattern() {
		return this.compiledPattern;
	}

	public void addListener(TextListener n) {
		this.listeners.add(n);
	}

	public void setQuery(String query, boolean removeDebugFlag) {
		this.query = query;
		this.removeDebugFlag = removeDebugFlag;
		this.compiledPattern = NotCompiledString;

	}
}