
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output;

import org.json.JSONObject;
import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableResolvedContentNodeVisitor;
import org.mitre.pickledcanary.search.Pattern;

public interface FormatVisitor extends VisitableResolvedContentNodeVisitor {
	/**
	 * Get the compiled pattern output as JSON.
	 * 
	 * @return JSON output
	 */
	JSONObject getOutput();

	/**
	 * Get the compiled pattern output as a {@link Pattern} object.
	 * 
	 * @return Pattern output
	 */
	Pattern getPattern();
}
