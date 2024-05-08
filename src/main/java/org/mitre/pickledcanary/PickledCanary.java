
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary;

import java.io.File;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;

import org.mitre.pickledcanary.patterngenerator.PCVisitor;
import org.mitre.pickledcanary.patterngenerator.generated.pc_grammar;
import org.mitre.pickledcanary.patterngenerator.generated.pc_lexer;
import org.mitre.pickledcanary.search.Pattern;
import org.mitre.pickledcanary.search.SavedDataAddresses;
import org.mitre.pickledcanary.search.VmSearch;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.TaskMonitor;

/**
 * This Class holds high-level static methods that are useful for parsing and/or searching pickled
 * canary patterns.
 */
public class PickledCanary {

	public static final boolean DEBUG = true;

	static class MyErrorListener extends BaseErrorListener {
		@Override
		public void syntaxError(Recognizer<?, ?> recognizer, Object offendingSymbol, int line,
				int charPositionInLine,
				String msg, RecognitionException e) {
			throw new RuntimeException("Pattern lexer encountered error when processing line " + line + ":" + charPositionInLine + " " + msg);
		}
	}
	
	/**
	 * Creates and runs the PC lexer and visitor across a given string pattern. The result can be
	 * used to generate a JSON or {@link Pattern} output.
	 * <p>
	 * You probably want to use {@link #compile(TaskMonitor, String, Program, Address, boolean)
	 * compile} or {@link #compile(TaskMonitor, String, Program, Address) compile} instead which
	 * handle these later steps for you as well. This is probably only useful if you're looking to
	 * capture both types of output later.
	 * 
	 * @param monitor
	 * @param pattern
	 *            The pattern to lex and visit.
	 * @param currentProgram
	 *            The program to use when lexing and visiting the given pattern.
	 * @param currentAddress
	 *            The address to use when lexing and visiting.
	 * @return PCVisitor instance which has already visited all nodes of the given pattern.
	 */
	public static PCVisitor createAndRunVisitor(TaskMonitor monitor, String pattern,
			final Program currentProgram, final Address currentAddress) {

		monitor.setIndeterminate(true);
		
		MyErrorListener errorListener = new MyErrorListener();

		var chars = CharStreams.fromString(pattern);
		var lexer = new pc_lexer(chars);
		lexer.addErrorListener(errorListener);
		var commonTokenStream = new CommonTokenStream(lexer);
		var parser = new pc_grammar(commonTokenStream);
		parser.addErrorListener(errorListener);

		var progContext = parser.prog();

		var visitor = new PCVisitor(currentProgram, currentAddress, monitor);
		visitor.visit(progContext);

		monitor.setIndeterminate(false);
		return visitor;
	}
	

	/**
	 * Returns a JSON string of the compiled pattern.
	 */
	public static String compile(TaskMonitor monitor, String pattern, Program program,
			Address address, boolean removeDebugInfo) {
		return createAndRunVisitor(monitor, pattern, program, address).getJSONObject(!removeDebugInfo).toString();
	}

	public static Pattern compile(TaskMonitor monitor, String pattern, Program program,
			Address address) {
		return createAndRunVisitor(monitor, pattern, program, address).getPattern();
	}

	/**
	 * Runs the given pattern, returning all results in the given program.
	 */
	public static List<SavedDataAddresses> parseAndRunAll(TaskMonitor monitor,
			Program program, Address address, String pattern) {
		Pattern patternCompiled = compileWrapped(monitor, pattern, program, address);

		return runAll(monitor, program, patternCompiled);
	}

	/**
	 * Runs the given pattern, returning all results in the given program.
	 */
	public static void parseAndRunAll(TaskMonitor monitor, Program program,
			Address address,
			Accumulator<SavedDataAddresses> accumulator, String pattern) {
		Pattern patternCompiled = compileWrapped(monitor, pattern, program, address);

		runAll(monitor, program, patternCompiled, accumulator);
	}

	/**
	 * Similar to compile, but adds a .* to the start of the pattern and adds instructions to record
	 * the start of the match and when the pattern has matched.
	 */
	public static Pattern compileWrapped(TaskMonitor monitor, String pattern, Program program,
			Address address) {
		PCVisitor visitor = createAndRunVisitor(monitor, pattern, program, address);
		return visitor.getPattern().wrap();
	}

	/**
	 * Runs the given pattern on the given program. You may prefer to use
	 * {@link #parseAndRunAll(TaskMonitor, String, Program, Address) parseAndRunAll}
	 */
	public static List<SavedDataAddresses> runAll(TaskMonitor monitor, Program program,
			Pattern pattern) {
		monitor.setMessage("Searching");
		VmSearch vm = new VmSearch(pattern, program.getMemory());

		return vm.runAll(monitor);
	}

	/**
	 * Runs the given pattern on the given program. You may prefer to use
	 * {@link #parseAndRunAll(TaskMonitor, String, Program, Address) parseAndRunAll}
	 */
	public static void runAll(TaskMonitor monitor, Program program, Pattern pattern,
			Accumulator<SavedDataAddresses> accumulator) {
		monitor.setMessage("Searching");
		VmSearch vm = new VmSearch(pattern, program.getMemory());

		vm.runAll(monitor, accumulator);
	}

	public enum AskFileType {
		Pattern, JSON
	}

	/**
	 * Custom version of Ghidra's {@code askFile} method. Allows user to select a file.
	 * 
	 * @param isSave
	 *            true if asking user to save JSON file; false if asking user to choose ptn file
	 * @return file object to read or write to
	 * @throws CancelledException
	 *             for if user clicks cancel button
	 */
	public static File pcAskFile(final boolean isSave, final AskFileType type, File previousFile)
			throws CancelledException {
		GhidraFileChooser chooser = new GhidraFileChooser(null);
		AtomicReference<File> ref = new AtomicReference<>();

		Runnable r = () -> {
			File selectedFile = previousFile;
			if (isSave) {
				if (previousFile != null) {
					// replace the .ptn extension with .json as the default output filename
					String ptnFileName = previousFile.getAbsolutePath();
					String jsonFileName;
					if ((type == AskFileType.JSON) && ptnFileName.endsWith(".ptn")) {
						jsonFileName = ptnFileName.replace(".ptn", ".json");
					}
					else {
						jsonFileName = ptnFileName;
					}
					selectedFile = new File(jsonFileName);
				}
			}
			chooser.setSelectedFile(selectedFile);

			chooser.setTitle(isSave ? "Save As" : "Choose the pattern file");
			chooser.setApproveButtonText(isSave ? "Save" : "Open");

			// set the file types to show in file choose
			chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			String extensionType = isSave ? "JSON" : "Pickled Canary";
			String extension = isSave ? "json" : "ptn";
			chooser.addFileFilter(ExtensionFileFilter.forExtensions(extensionType, extension));

			ref.set(chooser.getSelectedFile());
		};

		Swing.runNow(r);

		if (chooser.wasCancelled()) {
			throw new CancelledException();
		}

		return ref.get();
	}
}
