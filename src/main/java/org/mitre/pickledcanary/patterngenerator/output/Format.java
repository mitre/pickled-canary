
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output;

import org.mitre.pickledcanary.querylanguage.lexer.api.VisitableResolvedContentNode;

/**
 * Represents an output format of the compiled pattern.
 */
public interface Format {

	/**
	 * Add the binary representations of an annotated content node to the Format
	 * object.
	 * 
	 * @param resolvedContentNode the annotated resolvedContentNode of which binary
	 *                            representations are being added
	 */
	void addNextInstruction(final VisitableResolvedContentNode resolvedContentNode);

	/**
	 * Get a string of the binary representations from the patterns that have been
	 * added.
	 * 
	 * @return string of binary representations
	 */
	String getBinaryRepresentation();
}
