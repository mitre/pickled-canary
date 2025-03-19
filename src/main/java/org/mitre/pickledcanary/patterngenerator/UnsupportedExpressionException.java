// Copyright (C) 2025 The MITRE Corporation All Rights Reserved
package org.mitre.pickledcanary.patterngenerator;

import ghidra.app.plugin.processors.sleigh.expression.BinaryExpression;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.expression.UnaryExpression;

/**
 * Thrown when a passed expression could not be converted into a Picked Canary pattern.
 */
public class UnsupportedExpressionException extends RuntimeException {
	private static final long serialVersionUID = 4185835652675628001L;

	public UnsupportedExpressionException(PatternExpression expression) {
        super("Unsupported expression type: " + expression);
    }

    public UnsupportedExpressionException(UnaryExpression expression) {
        super("Unsupported unary expression type: " + expression);
    }

    public UnsupportedExpressionException(BinaryExpression expression) {
        super("Unsupported binary expression type: " + expression);
    }
}
