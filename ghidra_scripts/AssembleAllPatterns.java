
// Assemble all patterns in a Pickled Canary meta pattern
// @author MITRE

// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;

/**
 * Turns Pickled Canary assembly pattern into a compiled pattern that can be
 * used in the rust tool to search on binaries.
 */
public class AssembleAllPatterns extends GhidraScript {

	@Override
	protected void run() throws Exception {
		/// *
		monitor.setMessage("Choose assembly pattern to compile in dialog.");
		final File metaPatternFile = askFile("Choose meta pattern", "Open");

		final String metaPattern = Files.readString(metaPatternFile.toPath());

		final JSONObject metaPatternJson = new JSONObject(metaPattern);

		final JSONArray patterns = metaPatternJson.getJSONArray("patterns");

		for (int i = 0; i < patterns.length(); i++) {
			final JSONObject patternInfo = patterns.getJSONObject(i);
			final String name = patternInfo.getString("name");
			String filename = patternInfo.getString("file");

			if (filename.endsWith(".json")) {
				filename = filename.substring(0, filename.length() - 5) + ".ptn";
			} else {
				throw new RuntimeException("File " + filename + " in meta pattern does not end with '.json'!");
			}
			println("Parent: " + metaPatternFile.getParent() + "\n" + name + "\n" + filename + "\n");

			final Path patternPath = Paths.get(metaPatternFile.getParent(), filename);

			final List<String> pattern = Files.readAllLines(patternPath);
			boolean inMeta = false;
			StringBuilder meta = new StringBuilder();
			for (String line : pattern) {
				final String trimLine = line.trim();
				if (trimLine.startsWith(";")) {
					continue;
				}

				if (trimLine.contains("`META`")) {
					inMeta = true;
					continue;
				}
				if (trimLine.contains("`META_END`") || trimLine.contains("`END_META`")) {
					inMeta = false;
					continue;
				}
				if (inMeta) {
					meta.append(trimLine).append("\n");
				}
			}

			if (meta.length() < 2) {
				throw new RuntimeException("Didn't find meta block or meta block too short in file: " + patternPath);
			}
			
			final JSONObject metaBlock = new JSONObject(meta.toString());
			final JSONArray compileUsingList = metaBlock.getJSONArray("compile_using");
			for (int j = 0; j < compileUsingList.length(); j++) {
				final JSONObject compileInfo = compileUsingList.getJSONObject(j);
				println(compileInfo.toString());
			}

			final DomainFolder root = getProjectRootFolder();
			for (DomainFile f : root.getFiles()) {
				println(f.getPathname());
				final Map<String, String> fileMetadata = f.getMetadata();
//				if (fileMetadata.get("Executable MD5").compareTo(anotherString)))
				println(fileMetadata.toString());
			}
		}

		println("Done!");
	}
}
