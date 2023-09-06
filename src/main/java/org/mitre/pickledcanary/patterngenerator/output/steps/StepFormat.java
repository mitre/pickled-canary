
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;

import org.json.JSONObject;
import org.mitre.pickledcanary.patterngenerator.output.Format;
import org.mitre.pickledcanary.patterngenerator.output.FormatVisitor;
import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableResolvedContentNode;
import org.mitre.pickledcanary.search.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Output json format that contains steps.
 */
public class StepFormat implements Format {
	// the visitor to generate instruction-specific JSON output
	private final FormatVisitor formatVisitor;
	private final String executablePath;
	private final String executableMd5;
	private final String languageID;
	private final String currentAddress;

	public StepFormat(final Program currentProgram, final Address currentAddress, final TaskMonitor monitor) {
		formatVisitor = new StepFormatVisitor(currentProgram, currentAddress, monitor);
		this.executablePath = currentProgram.getExecutablePath();
		this.executableMd5 = currentProgram.getExecutableMD5();
		this.languageID = currentProgram.getLanguageID().getIdAsString();
		this.currentAddress = currentAddress.toString();
	}

	@Override
	public void addNextInstruction(final VisitableResolvedContentNode nextNode) {
		nextNode.accept(formatVisitor);
	}

	@Override
	public String getBinaryRepresentation() {
		JSONObject output = formatVisitor.getOutput();
		JSONObject compileInfo = new JSONObject();
		JSONObject sourceBinaryInfo = new JSONObject();
		sourceBinaryInfo.append("path", this.executablePath);
		sourceBinaryInfo.append("md5", this.executableMd5);
		sourceBinaryInfo.append("compiled_at_address", this.currentAddress);
		compileInfo.append("compiled_using_binary", sourceBinaryInfo);
		compileInfo.append("language_id", this.languageID);
		output.append("compile_info", compileInfo);

		return output.toString();
	}

	public Pattern getPattern() {
		// TODO: possibly add metadata
		return formatVisitor.getPattern();
	}

	public String getBinaryWithoutDebug() {
		JSONObject output = formatVisitor.getOutput();
		ArrayList<String> compileInfo = new ArrayList<>();
		output.put("compile_info", compileInfo);

		return output.toString();
	}
}
