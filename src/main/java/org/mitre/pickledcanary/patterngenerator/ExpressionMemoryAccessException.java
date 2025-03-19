// Copyright (C) 2025 The MITRE Corporation All Rights Reserved
package org.mitre.pickledcanary.patterngenerator;

import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Wrapped {@link MemoryAccessException} encountered while reading an expression.
 */
public class ExpressionMemoryAccessException extends RuntimeException {
	private static final long serialVersionUID = 4565756084196793376L;

	public ExpressionMemoryAccessException(PatternExpression expression, MemoryAccessException exception) {
        super("Invalid memory access while evaluating expression: " + expression, exception);
    }
}
