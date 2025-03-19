
/* ###
 * IP: GHIDRA 
 * REVIEWED: YES
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

/*
 * Based on Ghidra's sample SampleSearcher.
 */

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.searchInterface;

import java.awt.event.TextEvent;
import java.awt.event.TextListener;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;
import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.patterngenerator.PCVisitor;
import org.mitre.pickledcanary.search.Pattern;
import org.mitre.pickledcanary.search.SavedDataAddresses;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;

public class PickledCanarySearcher {

	public static final String BUILDING_PARSER = "Building assembly parser...";
	public static final String COMPILING_PATTERN = "Compiling Pattern...";
	public static final String NOT_COMPILED_STRING = "Compile pattern first!";

	private final Program program;
	private final Address currentAddress;
	private String query;
	private boolean removeDebugFlag;
	private final ArrayList<TextListener> listeners = new ArrayList<>();
	private String compiledPattern = NOT_COMPILED_STRING; // keeps track of if the pattern is
															 // compiling or not
	private PCVisitor visitor;
	List<AddressRange> range;

	public PickledCanarySearcher(Program program, Address currentAddress, String query) {
		this.program = program;
		this.currentAddress = currentAddress;
		this.query = query;
		this.removeDebugFlag = false;
		// If we initialize visitor here, the GUI doesn't show until the visitor is created. Instead
		// we'll initialize it on first search (which is immediately after the GUI opens)
		this.visitor = null;
	}

	private void notifyListeners() {
		for (TextListener listener : this.listeners) {
			listener.textValueChanged(new TextEvent(this, 900));
		}
	}

	public void search(Accumulator<SavedDataAddresses> accumulator, TaskMonitor monitor) {
		monitor.setMessage(PickledCanarySearcher.BUILDING_PARSER);
		if (this.visitor == null) {
			this.visitor = new PCVisitor(program, currentAddress, null);
		}
		else {
			this.visitor.reset();
		}

		// Don't try to search if a zero-length pattern given
		if (query.length() == 0) {
			return;
		}

		// Set our message to say that we're compiling... and tell everyone who cares
		this.compiledPattern = PickledCanarySearcher.COMPILING_PATTERN;
		this.notifyListeners();

		monitor.setMessage(PickledCanarySearcher.COMPILING_PATTERN);

		Instant start = Instant.now();

		// Parse and compile our pattern to json (and tell everyone who cares)
		visitor.setCurrentAddress(currentAddress);
		visitor.lexParseAndVisit(query, monitor);

		JSONObject o = visitor.getJSONObject(!removeDebugFlag);

		this.compiledPattern = o.toString(4);
		this.notifyListeners();

		// Now assemble our pattern into a Java-runnable pattern
		Pattern patternCompiled = visitor.getPattern().wrap();

		System.out.println("Ptn: " + patternCompiled.toString());

		Instant searchStart = Instant.now();
		// Run the pattern
		PickledCanary.runAll(monitor, program, patternCompiled, range, accumulator);

		Instant finish = Instant.now();

		Duration assembleDuration = Duration.between(start, searchStart);
		Duration searchDuration = Duration.between(searchStart, finish);

		System.out.println("Assembling took " + assembleDuration.getSeconds() + " seconds plus " +
			assembleDuration.getNano() + " nano-seconds");
		System.out.println("Searching took " + searchDuration.getSeconds() + " seconds plus " +
			searchDuration.getNano() + " nano-seconds");

		monitor.setIndeterminate(false);
	}

	public void setQuery(String query) {
		this.query = query;
		this.compiledPattern = NOT_COMPILED_STRING;
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
		this.compiledPattern = NOT_COMPILED_STRING;
	}

	public void setRange(
			List<AddressRange> newRange) {
		this.range = newRange;
	}
}