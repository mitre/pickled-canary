package org.mitre.pickledcanary.patterngenerator;

import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Wrapped {@link MemoryAccessException} encountered while reading an expression.
 */
public class ExpressionMemoryAccessException extends RuntimeException {
    public ExpressionMemoryAccessException(PatternExpression expression, MemoryAccessException exception) {
        super("Invalid memory access while evaluating expression: " + expression, exception);
    }
}
