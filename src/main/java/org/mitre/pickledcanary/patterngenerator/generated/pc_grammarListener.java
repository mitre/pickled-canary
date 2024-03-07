// Generated from pc_grammar.g4 by ANTLR 4.13.1

	package org.mitre.pickledcanary.patterngenerator.generated;

import org.antlr.v4.runtime.tree.ParseTreeListener;

/**
 * This interface defines a complete listener for a parse tree produced by
 * {@link pc_grammar}.
 */
public interface pc_grammarListener extends ParseTreeListener {
	/**
	 * Enter a parse tree produced by {@link pc_grammar#prog}.
	 * @param ctx the parse tree
	 */
	void enterProg(pc_grammar.ProgContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#prog}.
	 * @param ctx the parse tree
	 */
	void exitProg(pc_grammar.ProgContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#comment}.
	 * @param ctx the parse tree
	 */
	void enterComment(pc_grammar.CommentContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#comment}.
	 * @param ctx the parse tree
	 */
	void exitComment(pc_grammar.CommentContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#line}.
	 * @param ctx the parse tree
	 */
	void enterLine(pc_grammar.LineContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#line}.
	 * @param ctx the parse tree
	 */
	void exitLine(pc_grammar.LineContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#pc_command}.
	 * @param ctx the parse tree
	 */
	void enterPc_command(pc_grammar.Pc_commandContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#pc_command}.
	 * @param ctx the parse tree
	 */
	void exitPc_command(pc_grammar.Pc_commandContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#pc_command_body}.
	 * @param ctx the parse tree
	 */
	void enterPc_command_body(pc_grammar.Pc_command_bodyContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#pc_command_body}.
	 * @param ctx the parse tree
	 */
	void exitPc_command_body(pc_grammar.Pc_command_bodyContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#byte_match}.
	 * @param ctx the parse tree
	 */
	void enterByte_match(pc_grammar.Byte_matchContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#byte_match}.
	 * @param ctx the parse tree
	 */
	void exitByte_match(pc_grammar.Byte_matchContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#byte_string}.
	 * @param ctx the parse tree
	 */
	void enterByte_string(pc_grammar.Byte_stringContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#byte_string}.
	 * @param ctx the parse tree
	 */
	void exitByte_string(pc_grammar.Byte_stringContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#masked_byte}.
	 * @param ctx the parse tree
	 */
	void enterMasked_byte(pc_grammar.Masked_byteContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#masked_byte}.
	 * @param ctx the parse tree
	 */
	void exitMasked_byte(pc_grammar.Masked_byteContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#any_bytes}.
	 * @param ctx the parse tree
	 */
	void enterAny_bytes(pc_grammar.Any_bytesContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#any_bytes}.
	 * @param ctx the parse tree
	 */
	void exitAny_bytes(pc_grammar.Any_bytesContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#label}.
	 * @param ctx the parse tree
	 */
	void enterLabel(pc_grammar.LabelContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#label}.
	 * @param ctx the parse tree
	 */
	void exitLabel(pc_grammar.LabelContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#pc_block_command}.
	 * @param ctx the parse tree
	 */
	void enterPc_block_command(pc_grammar.Pc_block_commandContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#pc_block_command}.
	 * @param ctx the parse tree
	 */
	void exitPc_block_command(pc_grammar.Pc_block_commandContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#or_statement}.
	 * @param ctx the parse tree
	 */
	void enterOr_statement(pc_grammar.Or_statementContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#or_statement}.
	 * @param ctx the parse tree
	 */
	void exitOr_statement(pc_grammar.Or_statementContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#start_or}.
	 * @param ctx the parse tree
	 */
	void enterStart_or(pc_grammar.Start_orContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#start_or}.
	 * @param ctx the parse tree
	 */
	void exitStart_or(pc_grammar.Start_orContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#middle_or}.
	 * @param ctx the parse tree
	 */
	void enterMiddle_or(pc_grammar.Middle_orContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#middle_or}.
	 * @param ctx the parse tree
	 */
	void exitMiddle_or(pc_grammar.Middle_orContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#end_or}.
	 * @param ctx the parse tree
	 */
	void enterEnd_or(pc_grammar.End_orContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#end_or}.
	 * @param ctx the parse tree
	 */
	void exitEnd_or(pc_grammar.End_orContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#negative_lookahead}.
	 * @param ctx the parse tree
	 */
	void enterNegative_lookahead(pc_grammar.Negative_lookaheadContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#negative_lookahead}.
	 * @param ctx the parse tree
	 */
	void exitNegative_lookahead(pc_grammar.Negative_lookaheadContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#start_negative_lookahead}.
	 * @param ctx the parse tree
	 */
	void enterStart_negative_lookahead(pc_grammar.Start_negative_lookaheadContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#start_negative_lookahead}.
	 * @param ctx the parse tree
	 */
	void exitStart_negative_lookahead(pc_grammar.Start_negative_lookaheadContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#end_negative_lookahead}.
	 * @param ctx the parse tree
	 */
	void enterEnd_negative_lookahead(pc_grammar.End_negative_lookaheadContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#end_negative_lookahead}.
	 * @param ctx the parse tree
	 */
	void exitEnd_negative_lookahead(pc_grammar.End_negative_lookaheadContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#byte}.
	 * @param ctx the parse tree
	 */
	void enterByte(pc_grammar.ByteContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#byte}.
	 * @param ctx the parse tree
	 */
	void exitByte(pc_grammar.ByteContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#instruction}.
	 * @param ctx the parse tree
	 */
	void enterInstruction(pc_grammar.InstructionContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#instruction}.
	 * @param ctx the parse tree
	 */
	void exitInstruction(pc_grammar.InstructionContext ctx);
	/**
	 * Enter a parse tree produced by {@link pc_grammar#meta}.
	 * @param ctx the parse tree
	 */
	void enterMeta(pc_grammar.MetaContext ctx);
	/**
	 * Exit a parse tree produced by {@link pc_grammar#meta}.
	 * @param ctx the parse tree
	 */
	void exitMeta(pc_grammar.MetaContext ctx);
}