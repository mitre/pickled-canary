// Generated from pc_grammar.g4 by ANTLR 4.13.1

	package org.mitre.pickledcanary.patterngenerator.generated;

import org.antlr.v4.runtime.tree.ParseTreeVisitor;

/**
 * This interface defines a complete generic visitor for a parse tree produced
 * by {@link pc_grammar}.
 *
 * @param <T> The return type of the visit operation. Use {@link Void} for
 * operations with no return type.
 */
public interface pc_grammarVisitor<T> extends ParseTreeVisitor<T> {
	/**
	 * Visit a parse tree produced by {@link pc_grammar#prog}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitProg(pc_grammar.ProgContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#comment}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitComment(pc_grammar.CommentContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#line}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLine(pc_grammar.LineContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#pc_command}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitPc_command(pc_grammar.Pc_commandContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#pc_command_body}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitPc_command_body(pc_grammar.Pc_command_bodyContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#byte_match}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitByte_match(pc_grammar.Byte_matchContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#byte_string}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitByte_string(pc_grammar.Byte_stringContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#masked_byte}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitMasked_byte(pc_grammar.Masked_byteContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#any_bytes}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitAny_bytes(pc_grammar.Any_bytesContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#label}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLabel(pc_grammar.LabelContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#pc_block_command}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitPc_block_command(pc_grammar.Pc_block_commandContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#or_statement}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitOr_statement(pc_grammar.Or_statementContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#start_or}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitStart_or(pc_grammar.Start_orContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#middle_or}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitMiddle_or(pc_grammar.Middle_orContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#end_or}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitEnd_or(pc_grammar.End_orContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#negative_lookahead}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitNegative_lookahead(pc_grammar.Negative_lookaheadContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#start_negative_lookahead}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitStart_negative_lookahead(pc_grammar.Start_negative_lookaheadContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#end_negative_lookahead}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitEnd_negative_lookahead(pc_grammar.End_negative_lookaheadContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#byte}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitByte(pc_grammar.ByteContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#instruction}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitInstruction(pc_grammar.InstructionContext ctx);
	/**
	 * Visit a parse tree produced by {@link pc_grammar#meta}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitMeta(pc_grammar.MetaContext ctx);
}