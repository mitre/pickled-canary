// Copyright (C) 2025 The MITRE Corporation All Rights Reserved
package org.mitre.pickledcanary.patterngenerator;

import org.antlr.v4.runtime.ParserRuleContext;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupStep;

/**
 * Thrown when the query expression fails to parse.
 */
public class QueryParseException extends RuntimeException {

	private static final long serialVersionUID = -3411111699001185999L;

	public final String message;
    public final int lineNo;
    public final int columnNo;

    public QueryParseException(String message, int lineNo, int columnNo) {
        super("Failed to parse query at line " + lineNo + " col " + columnNo + ": " + message);
        this.message = message;
        this.lineNo = lineNo;
        this.columnNo = columnNo;
    }
    public QueryParseException(String message, ParserRuleContext ctx) {
        this(message + "\nCheck this line: '" + ctx.getText() + "'", ctx.start.getLine(), + ctx.start.getCharPositionInLine());
    }
    public QueryParseException(String message, LookupStep lookupStep) {
        this(message + "\nCheck this line: '" + lookupStep.getInstructionText() + "'", lookupStep.getLineNumber(), + lookupStep.getCharPosition());
    }
}
