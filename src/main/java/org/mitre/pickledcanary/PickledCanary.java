
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary;

import java.io.File;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.mitre.pickledcanary.patterngenerator.frontend.PatternAssembler;
import org.mitre.pickledcanary.patterngenerator.frontend.PatternAssembler.AssembleType;
import org.mitre.pickledcanary.querylanguage.lexer.Lexer;
import org.mitre.pickledcanary.querylanguage.lexer.ParseTree;
import org.mitre.pickledcanary.querylanguage.tokenizer.Token;
import org.mitre.pickledcanary.querylanguage.tokenizer.Tokenizer;
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
 * This Class holds high-level static methods that are useful for parsing and/or
 * searching pickled canary patterns.
 */
public class PickledCanary {

	/**
	 * You probably want to use
	 * {@link #parseAndAssemble(TaskMonitor, Program, Address, String, Boolean)
	 * parseAndAssemble} or
	 * {@link #parseAndRunAll(TaskMonitor, Program, Address, String) parseAndRunAll}
	 * instead.
	 */
	public static ParseTree parsePattern(TaskMonitor monitor, String query) {

		monitor.setIndeterminate(true);

		monitor.setMessage("Tokenizing query.");
		final Tokenizer tokenizer = new Tokenizer(query);

		final LinkedList<Token> tokens = tokenizer.tokenize(true);

		monitor.setMessage("Lexing query.");
		final Lexer lexer = new Lexer(tokens);

		ParseTree out = lexer.lex();

		monitor.setIndeterminate(false);
		return out;
	}

	private static Object assembleInternal(AssembleType type, TaskMonitor monitor, Program program,
			Address currentAddress, ParseTree parseTree, Boolean removeDebugInfo) {
		// start a transaction so that we can undo any overwrites we do to the binary
		int transactionID = program.startTransaction("Pickled Canary Pattern Assemble");

		monitor.setMessage("Creating pattern assembler");
		final PatternAssembler patternAssembler = new PatternAssembler();

		Object pattern;

		try {

			monitor.setMessage("Assembling pattern");

			pattern = patternAssembler.assemble(type, program, parseTree, currentAddress, program.getLanguage(),
					monitor, removeDebugInfo);

			// end transaction - discard all overwrites to the binary
			program.endTransaction(transactionID, false);

		} catch (Exception e) {
			// end transaction - discard all overwrites to the binary
			program.endTransaction(transactionID, false);
			throw e;
		}

		return pattern;
	}

	/**
	 * Returns a JSON string of the compiled pattern.
	 * <p>
	 * You probably want to use
	 * {@link #parseAndAssemble(TaskMonitor, Program, Address, String, Boolean)
	 * parseAndAssemble} instead.
	 */
	public static String assemble(TaskMonitor monitor, Program program, Address currentAddress, ParseTree parseTree) {
		return (String) assembleInternal(AssembleType.JSON, monitor, program, currentAddress, parseTree, false);
	}

	/**
	 * Returns a JSON string of the compiled pattern without the compile_info key
	 * information.
	 * <p>
	 * You probably want to use
	 * {@link #parseAndAssemble(TaskMonitor, Program, Address, String, Boolean)
	 * parseAndAssemble} instead.
	 */
	public static String assemble(TaskMonitor monitor, Program program, Address currentAddress, ParseTree parseTree,
			boolean removeDebugFlag) {
		return (String) assembleInternal(AssembleType.JSON, monitor, program, currentAddress, parseTree,
				removeDebugFlag);
	}

	/**
	 * Consider using
	 * {@link #assemblePatternWrapped(TaskMonitor, Program, Address, ParseTree)
	 * assemblePatternWrapped} which does the same thing as this function, but adds
	 * a starting .* and match instructions
	 */
	public static Pattern assemblePattern(TaskMonitor monitor, Program program, Address currentAddress,
			ParseTree parseTree) {
		return (Pattern) assembleInternal(AssembleType.PATTERN, monitor, program, currentAddress, parseTree, false);
	}

	/**
	 * This is the same as running {@link #parsePattern(TaskMonitor, String)
	 * parsePattern} followed by
	 * {@link #assemble(TaskMonitor, Program, Address, ParseTree) assemble).
	 * 
	 * Returns a compiled JSON pattern.
	 */
	public static String parseAndAssemble(TaskMonitor monitor, Program program, Address currentAddress, String query,
			Boolean removeDebugInfo) {

		final ParseTree parseTree = PickledCanary.parsePattern(monitor, query);
		return (String) assembleInternal(AssembleType.JSON, monitor, program, currentAddress, parseTree,
				removeDebugInfo);
	}

	/**
	 * Runs the given pattern (query), returning all results in the given program.
	 */
	public static List<SavedDataAddresses> parseAndRunAll(TaskMonitor monitor, Program program, Address currentAddress,
			String query) {
		final ParseTree parseTree = PickledCanary.parsePattern(monitor, query);

		Pattern pattern = assemblePatternWrapped(monitor, program, currentAddress, parseTree);

		return runAll(monitor, program, pattern);
	}

	/**
	 * Runs the given pattern (query), returning all results in the given program.
	 */
	public static void parseAndRunAll(TaskMonitor monitor, Program program, Address currentAddress, String query,
			Accumulator<SavedDataAddresses> accumulator) {
		final ParseTree parseTree = PickledCanary.parsePattern(monitor, query);

		Pattern pattern = assemblePatternWrapped(monitor, program, currentAddress, parseTree);

		runAll(monitor, program, pattern, accumulator);
	}

	/**
	 * Runs the given pattern (query), returning all results in the given program.
	 */
	public static String parseAssembleAndRunAll(TaskMonitor monitor, Program program, Address currentAddress,
			String query, Accumulator<SavedDataAddresses> accumulator) {
		final ParseTree parseTree = PickledCanary.parsePattern(monitor, query);

		Pattern pattern = assemblePatternWrapped(monitor, program, currentAddress, parseTree);

		runAll(monitor, program, pattern, accumulator);

		return assemble(monitor, program, currentAddress, parseTree);
	}

	/**
	 * Similar to assemblePattern, but adds a .* to the start of the pattern and
	 * adds instructions to record the start of the match and when the pattern has
	 * matched.
	 */
	public static Pattern assemblePatternWrapped(TaskMonitor monitor, Program program, Address currentAddress,
			ParseTree parseTree) {

		final Pattern pattern = assemblePattern(monitor, program, currentAddress, parseTree);

		monitor.setMessage("Preparing pattern");
		Pattern start = Pattern.getDotStar();
		start.append(Pattern.getSaveStart());
		pattern.prepend(start);
		pattern.append(Pattern.getMatch());
		return pattern;

	}

	/**
	 * Runs the given pattern on the given program. You may prefer to use
	 * {@link #parseAndRunAll(TaskMonitor, Program, Address, String) parseAndRunAll}
	 */
	public static List<SavedDataAddresses> runAll(TaskMonitor monitor, Program program, Pattern pattern) {
		monitor.setMessage("Searching");
		VmSearch vm = new VmSearch(pattern, program.getMemory());

		return vm.runAll(monitor);
	}

	/**
	 * Runs the given pattern on the given program. You may prefer to use
	 * {@link #parseAndRunAll(TaskMonitor, Program, Address, String) parseAndRunAll}
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
	 * Custom version of Ghidra's {@code askFile} method. Allows user to select a
	 * file.
	 * 
	 * @param isSave true if asking user to save JSON file; false if asking user to
	 *               choose ptn file
	 * @return file object to read or write to
	 * @throws CancelledException for if user clicks cancel button
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
					} else {
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
