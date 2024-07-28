package org.mitre.pickledcanary.patterngenerator;

import org.antlr.v4.runtime.ParserRuleContext;

/**
 * Thrown when the query expression fails to parse.
 */
public class QueryParseException extends RuntimeException {

    public final String message;
    public final int lineNo;
    public final int columnNo;

    public QueryParseException(String message, int lineNo, int columnNo) {
        super("Failed to parse query at line " +lineNo + " col " + columnNo + ": " + message);
        this.message = message;
        this.lineNo = lineNo;
        this.columnNo = columnNo;
    }
    public QueryParseException(String message, ParserRuleContext ctx) {
        this(message + "\nCheck this line: '" + ctx.getText() + "'", ctx.start.getLine(), + ctx.start.getCharPositionInLine());
    }
}
