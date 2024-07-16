// Pickled Canary script to compile an assembly pattern into a compiled pattern.
// @author MITRE

// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;

import org.mitre.pickledcanary.PickledCanary;

import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;

/**
 * Turns Pickled Canary assembly pattern into a compiled pattern that can be
 * used in the rust tool to search on binaries.
 */
public class AssemblePattern extends GhidraScript {
	private static File previousFile = null;

	@Override
	protected void run() throws Exception {
		monitor.setMessage("Choose assembly pattern to compile in dialog.");
		final File patternFile = PickledCanary.pcAskFile(false, PickledCanary.AskFileType.Pattern, previousFile);
		final boolean removeDebug = askYesNo("Remove Debug Information",
				"Would you like to remove the compile_info section of the compiled pattern?");
		previousFile = patternFile;
		final String query = Files.readString(patternFile.toPath());
		println("Processing query: " + query);

		final String pattern = PickledCanary.compile(monitor, query, currentProgram, currentAddress,
			removeDebug);

		// write compiled pattern to file
		if (!monitor.isCancelled()) {
			monitor.setMessage("Save the compiled pattern in dialog.");

			final File file = PickledCanary.pcAskFile(true, PickledCanary.AskFileType.JSON, previousFile);

			if (file.exists()) {
				final boolean overwrite = askYesNo("Confirm Save As",
						file.getName() + " already exists.\nDo you want to replace it?");
				if (!overwrite) {
					throw new CancelledException("User choose not to overwrite file.");
				}
			}
			final FileWriter fileWriter = new FileWriter(file);

			fileWriter.write(pattern);
			fileWriter.close();

			println("Assembled pattern! Pattern saved to " + file.getAbsolutePath());
		}

		println("Done!");
	}
}
