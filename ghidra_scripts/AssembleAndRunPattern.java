
// Pickled Canary script to compile an assembly pattern into a compiled pattern.
// @author MITRE

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

import java.io.File;
import java.nio.file.Files;
import java.util.List;

import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.search.SavedDataAddresses;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.util.exception.CancelledException;

/**
 * Turns Pickled Canary assembly pattern into a compiled pattern that can be
 * used in the rust tool to search on binaries.
 */
public class AssembleAndRunPattern extends GhidraScript {
	private static File previousFile = null;

	@Override
	protected void run() throws Exception {
		monitor.setMessage("Choose assembly pattern to compile in dialog.");
		final File patternFile = pcAskFile(false);
		previousFile = patternFile;
		final String query = Files.readString(patternFile.toPath());
		println("Processing query: " + query);

		List<SavedDataAddresses> result = PickledCanary.parseAndRunAll(monitor, currentProgram, currentAddress, query);

		if (result.size() == 0) {
			System.out.println("No match");
		} else {
			System.out.println("Match!");

			AddressSet set = new AddressSet();

			for (SavedDataAddresses x : result) {
				set.add(x.getStart(), x.getEnd().subtract(1));
			}

			createHighlight(set);
			System.out.println(result.toString());
		}

		println("Done!");
	}

	/**
	 * Custom version of Ghidra's {@code askFile} method. Allows user to select a
	 * file. This version shows only ptn and json files. When asking for which JSON
	 * file to write to, defaults to the ptn filename, with the .ptn extension
	 * replaced with .json.
	 *
	 * @param isSave true if asking user to save JSON file; false if asking user to
	 *               choose ptn file
	 * @return file object to read or write to
	 * @throws CancelledException for if user clicks cancel button
	 */
	private File pcAskFile(final boolean isSave) throws CancelledException {
		return PickledCanary.pcAskFile(isSave, PickledCanary.AskFileType.Pattern, previousFile);
	}
}
