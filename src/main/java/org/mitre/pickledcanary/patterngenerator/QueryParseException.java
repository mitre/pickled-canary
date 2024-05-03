package org.mitre.pickledcanary.patterngenerator;

import org.antlr.v4.runtime.ParserRuleContext;

/**
 * Thrown when the query expression fails to parse.
 */
public class QueryParseException extends RuntimeException {
    public QueryParseException(String message, ParserRuleContext ctx) {
        super("Failed to parse query: " + message + "\nCheck this line: '" + ctx.getText() + "'");
    }
}
