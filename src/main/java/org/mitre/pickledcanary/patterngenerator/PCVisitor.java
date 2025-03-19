// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;
import org.json.JSONArray;
import org.json.JSONObject;
import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.patterngenerator.ContextVisitor.ContextDebugEncoding;
import org.mitre.pickledcanary.patterngenerator.generated.pc_grammar;
import org.mitre.pickledcanary.patterngenerator.generated.pc_lexer;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupStep;
import org.mitre.pickledcanary.patterngenerator.output.steps.Step;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;
import org.mitre.pickledcanary.search.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * This class creates the generated pattern. There are three major steps to do this.
 * <p>
 * 1. Process the user pattern. This involves taking the token generated by the parser/lexer and
 * creating the steps for the pike VM to search. However, instruction tokens are ignored and
 * handled in step 2.
 * <p>
 * 2. Assemble instructions and make the pattern context-aware. An instruction can generate
 * different encodings, each of which can change the context to a different value. New branches in
 * the pattern are created for each context.
 * <p>
 * 3. Deduplicate equal branches. Branches are equal if the contents of the branch root nodes and
 * their children are the same. Deduplicating branches maintain the same paths, but duplicate
 * branches that traverse the same path are removed.
 */
public class PCVisitor {

	private final Program currentProgram;
	private Address currentAddress;
	private TaskMonitor monitor;

	private final MyErrorListener errorListener;
	private JSONObject metadata;
	private PatternContext currentContext; // contains output of first visitor
	private PatternContext outputContext; // contains output compiled pattern
	
	private Visitor visitor;
	private ContextVisitor contextVisitor;
	private PathDeduplicator pathDeduplicator;

	/**
	 * Construct visitor to build Step output.
	 *
	 * You likely want to call {@link #lexParseAndVisit(String, TaskMonitor)} once you've created an
	 * instance of this class. After that, {@link #getJSONObject(boolean)} or {@link #getPattern()}
	 * can be used to get the pattern output for export or searching respectively
	 *
	 * This visitor can be reused for multiple patterns IF the reset method is called between calls
	 * to {@link #lexParseAndVisit(String, TaskMonitor)}.
	 *
	 * @param currentProgram
	 * @param currentAddress
	 * @param monitor
	 */
	public PCVisitor(final Program currentProgram, final Address currentAddress,
			final TaskMonitor monitor) {
		this.currentProgram = currentProgram;
		this.currentAddress = currentAddress;
		this.monitor = monitor;

		errorListener = new MyErrorListener();
		this.currentContext = new PatternContext();
		this.metadata = new JSONObject();
		
		this.visitor = new Visitor(currentProgram);
		this.pathDeduplicator = new PathDeduplicator();
	}

	/**
	 * Reset back to state where this visitor can visit a new pattern.
	 */
	public void reset() {
		this.currentContext = new PatternContext();
		this.metadata = new JSONObject();
		this.visitor.reset();
	}

	/**
	 * Return the results of having processed the pattern as a {@link JSONObject} which can be used
	 * to output this compiled pattern.
	 *
	 * @param withDebugInfo Include an extra "compile_info" tag with debug information (or not)
	 * @return A {@link JSONObject} containing the processed equivalent of the last pattern visited.
	 */
	public JSONObject getJSONObject(boolean withDebugInfo) {
		this.outputContext.canonicalize();
		JSONObject output = this.outputContext.getJson(this.metadata);

		if (withDebugInfo) {
			output.append("compile_info", this.getDebugJson());
		}
		else {
			output.put("compile_info", new JSONArray());
		}

		return output;
	}

	/**
	 * Return the results of having processed the pattern as a {@link Pattern} which can be used to
	 * perform a search.
	 *
	 * @return A {@link Pattern} object containing the processed equivalent of the last pattern
	 *         visited.
	 */
	public Pattern getPattern() {
		this.outputContext.canonicalize();
		return this.outputContext.getPattern();
	}
	
	/**
	 * Get debug information about context for assembly instruction steps.
	 * Key is line number of instruction and the instruction text.
	 * ArrayList contains ContextDebugEncoding objects, each of which contains an encoding mask,
	 * encoding value, input context, and output context.
	 * @return context debug info
	 */
	public LinkedHashMap<String, ArrayList<ContextDebugEncoding>> getContextDebugInfo() {
		return this.contextVisitor.getContextDebugInfo();
	}

	private JSONObject getDebugJson() {
		JSONObject compileInfo = new JSONObject();
		JSONObject sourceBinaryInfo = new JSONObject();
		sourceBinaryInfo.append("path", this.currentProgram.getExecutablePath());
		sourceBinaryInfo.append("md5", this.currentProgram.getExecutableMD5());
		sourceBinaryInfo.append("compiled_at_address", this.currentAddress);
		compileInfo.append("compiled_using_binary", sourceBinaryInfo);
		compileInfo.append("language_id", this.currentProgram.getLanguageID().getIdAsString());
		return compileInfo;
	}

	protected record PatternContext(List<Step> steps, AllLookupTables tables) {
		PatternContext() {
			this(new ArrayList<>(), new AllLookupTables());
		}

		/**
		 * Replace temporary refs in the data structure with canonical id's.
		 */
		void canonicalize() {
			for (Step step : this.steps) {
				if (step instanceof LookupStep lookupStep) {
					lookupStep.resolveTableIds(this.tables);
				}
			}
		}

		Pattern getPattern() {
			return new Pattern(this.steps, this.tables.getPatternTables());
		}

		List<Step> getSteps() {
			return this.steps;
		}

		AllLookupTables getTables() {
			return this.tables;
		}
		
		/**
		 * Get raw JSON (without) any debug or compile info
		 *
		 * @return the JSON for this context
		 */
		JSONObject getJson(JSONObject metadata) {
			JSONObject out = new JSONObject();

			JSONArray arr = new JSONArray();
			for (Step step : steps) {
				arr.put(step.getJson());
			}
			out.put("steps", arr);
			out.put("tables", tables.getJson());
			out.put("pattern_metadata", metadata);
			return out;
		}
	}

	/**
	 * Update the address used by this visitor to assemble given instructions.
	 *
	 * @param address The address that we want to compile at
	 */
	public void setCurrentAddress(Address address) {
		currentAddress = address;
	}

	public void setMonitor(TaskMonitor m) {
		monitor = m;
	}

	private static class MyErrorListener extends BaseErrorListener {
		@Override
		public void syntaxError(Recognizer<?, ?> recognizer, Object offendingSymbol, int line,
				int charPositionInLine, String msg, RecognitionException e) {
			throw new QueryParseException(msg, line, charPositionInLine);
		}
	}

	/**
	 * Process the given pattern, making results available in {@link #getPattern()} or
	 * {@link #getJSONObject(boolean)} methods.
	 *
	 * Call {@link #reset()} in between calls to this method if reusing this instance. If
	 * currentAddress has changed since this instance was created, call
	 * {@link #setCurrentAddress(Address)} before calling this method
	 *
	 * @param pattern    The pattern string to parse into steps
	 * @param newMonitor A monitor to display progress
	 */
	public void lexParseAndVisit(String pattern, TaskMonitor newMonitor) {
		monitor = newMonitor;
		monitor.setIndeterminate(true);

		var chars = CharStreams.fromString(pattern);
		var lexer = new pc_lexer(chars);
		lexer.addErrorListener(errorListener);
		var commonTokenStream = new CommonTokenStream(lexer);
		var parser = new pc_grammar(commonTokenStream);
		parser.addErrorListener(errorListener);

		var progContext = parser.prog();

		/* Step 1 */
		this.currentContext = visitor.getContext(progContext);
		this.metadata = visitor.getMetadata();
		
		/* Step 2 */
		this.contextVisitor = new ContextVisitor(currentProgram, currentAddress, monitor, currentContext);
		PatternContext contextAwareContext = contextVisitor.makeContextAware();
		
		/* Step 3 */
		this.outputContext = pathDeduplicator.deduplicatePaths(contextAwareContext);

		if (PickledCanary.DEBUG) {
			System.out.println("initial pattern");
			for (int i = 0; i < currentContext.steps.size(); i++) {
				System.out.println(i + ": " + currentContext.steps.get(i));
			}

			System.out.println("context pattern");
			for (int i = 0; i < contextVisitor.contextAwareContext.steps.size(); i++) {
				System.out.println(i + ": " + contextVisitor.contextAwareContext.steps.get(i));
			}

			System.out.println("final pattern");
			for (int i = 0; i < outputContext.steps.size(); i++) {
				System.out.println(i + ": " + outputContext.steps.get(i));
			}
			
			System.out.println("Context debug");
			for (String instr : this.getContextDebugInfo().keySet()) {
				System.out.println(instr);
				for (ContextDebugEncoding cde : this.getContextDebugInfo().get(instr)) {
					System.out.print("\t");
					for (byte b : cde.encodingMask()) {
						System.out.print(b + " ");
					}
					System.out.print("   ");
					for (byte b : cde.encodingValue()) {
						System.out.print(b + " ");
					}
					System.out.println("   " + cde.inputContext() + " " + cde.outputContext());
				}
			}
		}

		monitor.setIndeterminate(false);
	}
}
