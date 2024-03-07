// Generated from pc_grammar.g4 by ANTLR 4.13.1

	package org.mitre.pickledcanary.patterngenerator.generated;

import org.antlr.v4.runtime.atn.*;
import org.antlr.v4.runtime.dfa.DFA;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.misc.*;
import org.antlr.v4.runtime.tree.*;
import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;

@SuppressWarnings({"all", "warnings", "unchecked", "unused", "cast", "CheckReturnValue"})
public class pc_grammar extends Parser {
	static { RuntimeMetaData.checkVersion("4.13.1", RuntimeMetaData.VERSION); }

	protected static final DFA[] _decisionToDFA;
	protected static final PredictionContextCache _sharedContextCache =
		new PredictionContextCache();
	public static final int
		SEMICOLON=1, NEWLINE=2, COMMENT=3, TICK=4, START_OR=5, MIDDLE_OR=6, END_OR=7, 
		START_NEGATIVE_LOOKAHEAD=8, END_NEGATIVE_LOOKAHEAD=9, INSTRUCTION=10, 
		META=11, BYTE_PREFIX=12, MASKED_BYTE_PREFIX=13, ANY_BYTES=14, COMMA_SEPARATOR=15, 
		CLOSE_BRACE=16, MIXED_NUMBER=17, LABEL=18, BYTE_STRING=19, EXIT_TICK=20, 
		BYTE=21;
	public static final int
		RULE_prog = 0, RULE_comment = 1, RULE_line = 2, RULE_pc_command = 3, RULE_pc_command_body = 4, 
		RULE_byte_match = 5, RULE_byte_string = 6, RULE_masked_byte = 7, RULE_any_bytes = 8, 
		RULE_label = 9, RULE_pc_block_command = 10, RULE_or_statement = 11, RULE_start_or = 12, 
		RULE_middle_or = 13, RULE_end_or = 14, RULE_negative_lookahead = 15, RULE_start_negative_lookahead = 16, 
		RULE_end_negative_lookahead = 17, RULE_byte = 18, RULE_instruction = 19, 
		RULE_meta = 20;
	private static String[] makeRuleNames() {
		return new String[] {
			"prog", "comment", "line", "pc_command", "pc_command_body", "byte_match", 
			"byte_string", "masked_byte", "any_bytes", "label", "pc_block_command", 
			"or_statement", "start_or", "middle_or", "end_or", "negative_lookahead", 
			"start_negative_lookahead", "end_negative_lookahead", "byte", "instruction", 
			"meta"
		};
	}
	public static final String[] ruleNames = makeRuleNames();

	private static String[] makeLiteralNames() {
		return new String[] {
			null, "';'", null, null, null, null, null, null, null, null, null, null, 
			"'='", "'&'", null, null, "'}'", null, null, null, "'`'"
		};
	}
	private static final String[] _LITERAL_NAMES = makeLiteralNames();
	private static String[] makeSymbolicNames() {
		return new String[] {
			null, "SEMICOLON", "NEWLINE", "COMMENT", "TICK", "START_OR", "MIDDLE_OR", 
			"END_OR", "START_NEGATIVE_LOOKAHEAD", "END_NEGATIVE_LOOKAHEAD", "INSTRUCTION", 
			"META", "BYTE_PREFIX", "MASKED_BYTE_PREFIX", "ANY_BYTES", "COMMA_SEPARATOR", 
			"CLOSE_BRACE", "MIXED_NUMBER", "LABEL", "BYTE_STRING", "EXIT_TICK", "BYTE"
		};
	}
	private static final String[] _SYMBOLIC_NAMES = makeSymbolicNames();
	public static final Vocabulary VOCABULARY = new VocabularyImpl(_LITERAL_NAMES, _SYMBOLIC_NAMES);

	/**
	 * @deprecated Use {@link #VOCABULARY} instead.
	 */
	@Deprecated
	public static final String[] tokenNames;
	static {
		tokenNames = new String[_SYMBOLIC_NAMES.length];
		for (int i = 0; i < tokenNames.length; i++) {
			tokenNames[i] = VOCABULARY.getLiteralName(i);
			if (tokenNames[i] == null) {
				tokenNames[i] = VOCABULARY.getSymbolicName(i);
			}

			if (tokenNames[i] == null) {
				tokenNames[i] = "<INVALID>";
			}
		}
	}

	@Override
	@Deprecated
	public String[] getTokenNames() {
		return tokenNames;
	}

	@Override

	public Vocabulary getVocabulary() {
		return VOCABULARY;
	}

	@Override
	public String getGrammarFileName() { return "pc_grammar.g4"; }

	@Override
	public String[] getRuleNames() { return ruleNames; }

	@Override
	public String getSerializedATN() { return _serializedATN; }

	@Override
	public ATN getATN() { return _ATN; }

	public pc_grammar(TokenStream input) {
		super(input);
		_interp = new ParserATNSimulator(this,_ATN,_decisionToDFA,_sharedContextCache);
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ProgContext extends ParserRuleContext {
		public List<LineContext> line() {
			return getRuleContexts(LineContext.class);
		}
		public LineContext line(int i) {
			return getRuleContext(LineContext.class,i);
		}
		public TerminalNode EOF() { return getToken(pc_grammar.EOF, 0); }
		public List<TerminalNode> NEWLINE() { return getTokens(pc_grammar.NEWLINE); }
		public TerminalNode NEWLINE(int i) {
			return getToken(pc_grammar.NEWLINE, i);
		}
		public ProgContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_prog; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterProg(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitProg(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitProg(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ProgContext prog() throws RecognitionException {
		ProgContext _localctx = new ProgContext(_ctx, getState());
		enterRule(_localctx, 0, RULE_prog);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(42);
			line();
			setState(51);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,1,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(44); 
					_errHandler.sync(this);
					_la = _input.LA(1);
					do {
						{
						{
						setState(43);
						match(NEWLINE);
						}
						}
						setState(46); 
						_errHandler.sync(this);
						_la = _input.LA(1);
					} while ( _la==NEWLINE );
					setState(48);
					line();
					}
					} 
				}
				setState(53);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,1,_ctx);
			}
			setState(57);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==NEWLINE) {
				{
				{
				setState(54);
				match(NEWLINE);
				}
				}
				setState(59);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(60);
			match(EOF);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class CommentContext extends ParserRuleContext {
		public TerminalNode COMMENT() { return getToken(pc_grammar.COMMENT, 0); }
		public CommentContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_comment; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterComment(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitComment(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitComment(this);
			else return visitor.visitChildren(this);
		}
	}

	public final CommentContext comment() throws RecognitionException {
		CommentContext _localctx = new CommentContext(_ctx, getState());
		enterRule(_localctx, 2, RULE_comment);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(62);
			match(COMMENT);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class LineContext extends ParserRuleContext {
		public CommentContext comment() {
			return getRuleContext(CommentContext.class,0);
		}
		public Pc_commandContext pc_command() {
			return getRuleContext(Pc_commandContext.class,0);
		}
		public Pc_block_commandContext pc_block_command() {
			return getRuleContext(Pc_block_commandContext.class,0);
		}
		public InstructionContext instruction() {
			return getRuleContext(InstructionContext.class,0);
		}
		public MetaContext meta() {
			return getRuleContext(MetaContext.class,0);
		}
		public LineContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_line; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterLine(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitLine(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitLine(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LineContext line() throws RecognitionException {
		LineContext _localctx = new LineContext(_ctx, getState());
		enterRule(_localctx, 4, RULE_line);
		try {
			setState(69);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case COMMENT:
				enterOuterAlt(_localctx, 1);
				{
				setState(64);
				comment();
				}
				break;
			case TICK:
				enterOuterAlt(_localctx, 2);
				{
				setState(65);
				pc_command();
				}
				break;
			case START_OR:
			case START_NEGATIVE_LOOKAHEAD:
				enterOuterAlt(_localctx, 3);
				{
				setState(66);
				pc_block_command();
				}
				break;
			case INSTRUCTION:
				enterOuterAlt(_localctx, 4);
				{
				setState(67);
				instruction();
				}
				break;
			case META:
				enterOuterAlt(_localctx, 5);
				{
				setState(68);
				meta();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Pc_commandContext extends ParserRuleContext {
		public TerminalNode TICK() { return getToken(pc_grammar.TICK, 0); }
		public Pc_command_bodyContext pc_command_body() {
			return getRuleContext(Pc_command_bodyContext.class,0);
		}
		public TerminalNode EXIT_TICK() { return getToken(pc_grammar.EXIT_TICK, 0); }
		public Pc_commandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_pc_command; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterPc_command(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitPc_command(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitPc_command(this);
			else return visitor.visitChildren(this);
		}
	}

	public final Pc_commandContext pc_command() throws RecognitionException {
		Pc_commandContext _localctx = new Pc_commandContext(_ctx, getState());
		enterRule(_localctx, 6, RULE_pc_command);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(71);
			match(TICK);
			setState(72);
			pc_command_body();
			setState(73);
			match(EXIT_TICK);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Pc_command_bodyContext extends ParserRuleContext {
		public Byte_matchContext byte_match() {
			return getRuleContext(Byte_matchContext.class,0);
		}
		public Byte_stringContext byte_string() {
			return getRuleContext(Byte_stringContext.class,0);
		}
		public Masked_byteContext masked_byte() {
			return getRuleContext(Masked_byteContext.class,0);
		}
		public Any_bytesContext any_bytes() {
			return getRuleContext(Any_bytesContext.class,0);
		}
		public LabelContext label() {
			return getRuleContext(LabelContext.class,0);
		}
		public Pc_command_bodyContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_pc_command_body; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterPc_command_body(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitPc_command_body(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitPc_command_body(this);
			else return visitor.visitChildren(this);
		}
	}

	public final Pc_command_bodyContext pc_command_body() throws RecognitionException {
		Pc_command_bodyContext _localctx = new Pc_command_bodyContext(_ctx, getState());
		enterRule(_localctx, 8, RULE_pc_command_body);
		try {
			setState(80);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case BYTE_PREFIX:
				enterOuterAlt(_localctx, 1);
				{
				setState(75);
				byte_match();
				}
				break;
			case BYTE_STRING:
				enterOuterAlt(_localctx, 2);
				{
				setState(76);
				byte_string();
				}
				break;
			case MASKED_BYTE_PREFIX:
				enterOuterAlt(_localctx, 3);
				{
				setState(77);
				masked_byte();
				}
				break;
			case ANY_BYTES:
				enterOuterAlt(_localctx, 4);
				{
				setState(78);
				any_bytes();
				}
				break;
			case LABEL:
				enterOuterAlt(_localctx, 5);
				{
				setState(79);
				label();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Byte_matchContext extends ParserRuleContext {
		public TerminalNode BYTE_PREFIX() { return getToken(pc_grammar.BYTE_PREFIX, 0); }
		public ByteContext byte_() {
			return getRuleContext(ByteContext.class,0);
		}
		public Byte_matchContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_byte_match; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterByte_match(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitByte_match(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitByte_match(this);
			else return visitor.visitChildren(this);
		}
	}

	public final Byte_matchContext byte_match() throws RecognitionException {
		Byte_matchContext _localctx = new Byte_matchContext(_ctx, getState());
		enterRule(_localctx, 10, RULE_byte_match);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(82);
			match(BYTE_PREFIX);
			setState(83);
			byte_();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Byte_stringContext extends ParserRuleContext {
		public TerminalNode BYTE_STRING() { return getToken(pc_grammar.BYTE_STRING, 0); }
		public Byte_stringContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_byte_string; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterByte_string(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitByte_string(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitByte_string(this);
			else return visitor.visitChildren(this);
		}
	}

	public final Byte_stringContext byte_string() throws RecognitionException {
		Byte_stringContext _localctx = new Byte_stringContext(_ctx, getState());
		enterRule(_localctx, 12, RULE_byte_string);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(85);
			match(BYTE_STRING);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Masked_byteContext extends ParserRuleContext {
		public TerminalNode MASKED_BYTE_PREFIX() { return getToken(pc_grammar.MASKED_BYTE_PREFIX, 0); }
		public List<ByteContext> byte_() {
			return getRuleContexts(ByteContext.class);
		}
		public ByteContext byte_(int i) {
			return getRuleContext(ByteContext.class,i);
		}
		public TerminalNode BYTE_PREFIX() { return getToken(pc_grammar.BYTE_PREFIX, 0); }
		public Masked_byteContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_masked_byte; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterMasked_byte(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitMasked_byte(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitMasked_byte(this);
			else return visitor.visitChildren(this);
		}
	}

	public final Masked_byteContext masked_byte() throws RecognitionException {
		Masked_byteContext _localctx = new Masked_byteContext(_ctx, getState());
		enterRule(_localctx, 14, RULE_masked_byte);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(87);
			match(MASKED_BYTE_PREFIX);
			setState(88);
			byte_();
			setState(89);
			match(BYTE_PREFIX);
			setState(90);
			byte_();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Any_bytesContext extends ParserRuleContext {
		public TerminalNode ANY_BYTES() { return getToken(pc_grammar.ANY_BYTES, 0); }
		public List<TerminalNode> MIXED_NUMBER() { return getTokens(pc_grammar.MIXED_NUMBER); }
		public TerminalNode MIXED_NUMBER(int i) {
			return getToken(pc_grammar.MIXED_NUMBER, i);
		}
		public List<TerminalNode> COMMA_SEPARATOR() { return getTokens(pc_grammar.COMMA_SEPARATOR); }
		public TerminalNode COMMA_SEPARATOR(int i) {
			return getToken(pc_grammar.COMMA_SEPARATOR, i);
		}
		public TerminalNode CLOSE_BRACE() { return getToken(pc_grammar.CLOSE_BRACE, 0); }
		public Any_bytesContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_any_bytes; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterAny_bytes(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitAny_bytes(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitAny_bytes(this);
			else return visitor.visitChildren(this);
		}
	}

	public final Any_bytesContext any_bytes() throws RecognitionException {
		Any_bytesContext _localctx = new Any_bytesContext(_ctx, getState());
		enterRule(_localctx, 16, RULE_any_bytes);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(92);
			match(ANY_BYTES);
			setState(93);
			match(MIXED_NUMBER);
			setState(94);
			match(COMMA_SEPARATOR);
			setState(95);
			match(MIXED_NUMBER);
			setState(98);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==COMMA_SEPARATOR) {
				{
				setState(96);
				match(COMMA_SEPARATOR);
				setState(97);
				match(MIXED_NUMBER);
				}
			}

			setState(100);
			match(CLOSE_BRACE);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class LabelContext extends ParserRuleContext {
		public TerminalNode LABEL() { return getToken(pc_grammar.LABEL, 0); }
		public LabelContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_label; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterLabel(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitLabel(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitLabel(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LabelContext label() throws RecognitionException {
		LabelContext _localctx = new LabelContext(_ctx, getState());
		enterRule(_localctx, 18, RULE_label);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(102);
			match(LABEL);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Pc_block_commandContext extends ParserRuleContext {
		public Or_statementContext or_statement() {
			return getRuleContext(Or_statementContext.class,0);
		}
		public Negative_lookaheadContext negative_lookahead() {
			return getRuleContext(Negative_lookaheadContext.class,0);
		}
		public Pc_block_commandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_pc_block_command; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterPc_block_command(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitPc_block_command(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitPc_block_command(this);
			else return visitor.visitChildren(this);
		}
	}

	public final Pc_block_commandContext pc_block_command() throws RecognitionException {
		Pc_block_commandContext _localctx = new Pc_block_commandContext(_ctx, getState());
		enterRule(_localctx, 20, RULE_pc_block_command);
		try {
			setState(106);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case START_OR:
				enterOuterAlt(_localctx, 1);
				{
				setState(104);
				or_statement();
				}
				break;
			case START_NEGATIVE_LOOKAHEAD:
				enterOuterAlt(_localctx, 2);
				{
				setState(105);
				negative_lookahead();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Or_statementContext extends ParserRuleContext {
		public Start_orContext start_or() {
			return getRuleContext(Start_orContext.class,0);
		}
		public End_orContext end_or() {
			return getRuleContext(End_orContext.class,0);
		}
		public List<LineContext> line() {
			return getRuleContexts(LineContext.class);
		}
		public LineContext line(int i) {
			return getRuleContext(LineContext.class,i);
		}
		public List<Middle_orContext> middle_or() {
			return getRuleContexts(Middle_orContext.class);
		}
		public Middle_orContext middle_or(int i) {
			return getRuleContext(Middle_orContext.class,i);
		}
		public List<TerminalNode> NEWLINE() { return getTokens(pc_grammar.NEWLINE); }
		public TerminalNode NEWLINE(int i) {
			return getToken(pc_grammar.NEWLINE, i);
		}
		public Or_statementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_or_statement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterOr_statement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitOr_statement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitOr_statement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final Or_statementContext or_statement() throws RecognitionException {
		Or_statementContext _localctx = new Or_statementContext(_ctx, getState());
		enterRule(_localctx, 22, RULE_or_statement);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(108);
			start_or();
			setState(115); 
			_errHandler.sync(this);
			_la = _input.LA(1);
			do {
				{
				{
				setState(109);
				line();
				setState(111); 
				_errHandler.sync(this);
				_la = _input.LA(1);
				do {
					{
					{
					setState(110);
					match(NEWLINE);
					}
					}
					setState(113); 
					_errHandler.sync(this);
					_la = _input.LA(1);
				} while ( _la==NEWLINE );
				}
				}
				setState(117); 
				_errHandler.sync(this);
				_la = _input.LA(1);
			} while ( (((_la) & ~0x3f) == 0 && ((1L << _la) & 3384L) != 0) );
			setState(132);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==MIDDLE_OR) {
				{
				{
				setState(119);
				middle_or();
				setState(126); 
				_errHandler.sync(this);
				_la = _input.LA(1);
				do {
					{
					{
					setState(120);
					line();
					setState(122); 
					_errHandler.sync(this);
					_la = _input.LA(1);
					do {
						{
						{
						setState(121);
						match(NEWLINE);
						}
						}
						setState(124); 
						_errHandler.sync(this);
						_la = _input.LA(1);
					} while ( _la==NEWLINE );
					}
					}
					setState(128); 
					_errHandler.sync(this);
					_la = _input.LA(1);
				} while ( (((_la) & ~0x3f) == 0 && ((1L << _la) & 3384L) != 0) );
				}
				}
				setState(134);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(135);
			end_or();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Start_orContext extends ParserRuleContext {
		public TerminalNode START_OR() { return getToken(pc_grammar.START_OR, 0); }
		public Start_orContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_start_or; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterStart_or(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitStart_or(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitStart_or(this);
			else return visitor.visitChildren(this);
		}
	}

	public final Start_orContext start_or() throws RecognitionException {
		Start_orContext _localctx = new Start_orContext(_ctx, getState());
		enterRule(_localctx, 24, RULE_start_or);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(137);
			match(START_OR);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Middle_orContext extends ParserRuleContext {
		public TerminalNode MIDDLE_OR() { return getToken(pc_grammar.MIDDLE_OR, 0); }
		public Middle_orContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_middle_or; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterMiddle_or(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitMiddle_or(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitMiddle_or(this);
			else return visitor.visitChildren(this);
		}
	}

	public final Middle_orContext middle_or() throws RecognitionException {
		Middle_orContext _localctx = new Middle_orContext(_ctx, getState());
		enterRule(_localctx, 26, RULE_middle_or);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(139);
			match(MIDDLE_OR);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class End_orContext extends ParserRuleContext {
		public TerminalNode END_OR() { return getToken(pc_grammar.END_OR, 0); }
		public End_orContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_end_or; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterEnd_or(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitEnd_or(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitEnd_or(this);
			else return visitor.visitChildren(this);
		}
	}

	public final End_orContext end_or() throws RecognitionException {
		End_orContext _localctx = new End_orContext(_ctx, getState());
		enterRule(_localctx, 28, RULE_end_or);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(141);
			match(END_OR);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Negative_lookaheadContext extends ParserRuleContext {
		public Start_negative_lookaheadContext start_negative_lookahead() {
			return getRuleContext(Start_negative_lookaheadContext.class,0);
		}
		public End_negative_lookaheadContext end_negative_lookahead() {
			return getRuleContext(End_negative_lookaheadContext.class,0);
		}
		public List<LineContext> line() {
			return getRuleContexts(LineContext.class);
		}
		public LineContext line(int i) {
			return getRuleContext(LineContext.class,i);
		}
		public List<TerminalNode> NEWLINE() { return getTokens(pc_grammar.NEWLINE); }
		public TerminalNode NEWLINE(int i) {
			return getToken(pc_grammar.NEWLINE, i);
		}
		public Negative_lookaheadContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_negative_lookahead; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterNegative_lookahead(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitNegative_lookahead(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitNegative_lookahead(this);
			else return visitor.visitChildren(this);
		}
	}

	public final Negative_lookaheadContext negative_lookahead() throws RecognitionException {
		Negative_lookaheadContext _localctx = new Negative_lookaheadContext(_ctx, getState());
		enterRule(_localctx, 30, RULE_negative_lookahead);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(143);
			start_negative_lookahead();
			setState(150); 
			_errHandler.sync(this);
			_la = _input.LA(1);
			do {
				{
				{
				setState(144);
				line();
				setState(146); 
				_errHandler.sync(this);
				_la = _input.LA(1);
				do {
					{
					{
					setState(145);
					match(NEWLINE);
					}
					}
					setState(148); 
					_errHandler.sync(this);
					_la = _input.LA(1);
				} while ( _la==NEWLINE );
				}
				}
				setState(152); 
				_errHandler.sync(this);
				_la = _input.LA(1);
			} while ( (((_la) & ~0x3f) == 0 && ((1L << _la) & 3384L) != 0) );
			setState(154);
			end_negative_lookahead();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Start_negative_lookaheadContext extends ParserRuleContext {
		public TerminalNode START_NEGATIVE_LOOKAHEAD() { return getToken(pc_grammar.START_NEGATIVE_LOOKAHEAD, 0); }
		public Start_negative_lookaheadContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_start_negative_lookahead; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterStart_negative_lookahead(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitStart_negative_lookahead(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitStart_negative_lookahead(this);
			else return visitor.visitChildren(this);
		}
	}

	public final Start_negative_lookaheadContext start_negative_lookahead() throws RecognitionException {
		Start_negative_lookaheadContext _localctx = new Start_negative_lookaheadContext(_ctx, getState());
		enterRule(_localctx, 32, RULE_start_negative_lookahead);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(156);
			match(START_NEGATIVE_LOOKAHEAD);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class End_negative_lookaheadContext extends ParserRuleContext {
		public TerminalNode END_NEGATIVE_LOOKAHEAD() { return getToken(pc_grammar.END_NEGATIVE_LOOKAHEAD, 0); }
		public End_negative_lookaheadContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_end_negative_lookahead; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterEnd_negative_lookahead(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitEnd_negative_lookahead(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitEnd_negative_lookahead(this);
			else return visitor.visitChildren(this);
		}
	}

	public final End_negative_lookaheadContext end_negative_lookahead() throws RecognitionException {
		End_negative_lookaheadContext _localctx = new End_negative_lookaheadContext(_ctx, getState());
		enterRule(_localctx, 34, RULE_end_negative_lookahead);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(158);
			match(END_NEGATIVE_LOOKAHEAD);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ByteContext extends ParserRuleContext {
		public TerminalNode BYTE() { return getToken(pc_grammar.BYTE, 0); }
		public ByteContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_byte; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterByte(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitByte(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitByte(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ByteContext byte_() throws RecognitionException {
		ByteContext _localctx = new ByteContext(_ctx, getState());
		enterRule(_localctx, 36, RULE_byte);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(160);
			match(BYTE);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class InstructionContext extends ParserRuleContext {
		public TerminalNode INSTRUCTION() { return getToken(pc_grammar.INSTRUCTION, 0); }
		public InstructionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_instruction; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterInstruction(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitInstruction(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitInstruction(this);
			else return visitor.visitChildren(this);
		}
	}

	public final InstructionContext instruction() throws RecognitionException {
		InstructionContext _localctx = new InstructionContext(_ctx, getState());
		enterRule(_localctx, 38, RULE_instruction);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(162);
			match(INSTRUCTION);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class MetaContext extends ParserRuleContext {
		public TerminalNode META() { return getToken(pc_grammar.META, 0); }
		public MetaContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_meta; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).enterMeta(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof pc_grammarListener ) ((pc_grammarListener)listener).exitMeta(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof pc_grammarVisitor ) return ((pc_grammarVisitor<? extends T>)visitor).visitMeta(this);
			else return visitor.visitChildren(this);
		}
	}

	public final MetaContext meta() throws RecognitionException {
		MetaContext _localctx = new MetaContext(_ctx, getState());
		enterRule(_localctx, 40, RULE_meta);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(164);
			match(META);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static final String _serializedATN =
		"\u0004\u0001\u0015\u00a7\u0002\u0000\u0007\u0000\u0002\u0001\u0007\u0001"+
		"\u0002\u0002\u0007\u0002\u0002\u0003\u0007\u0003\u0002\u0004\u0007\u0004"+
		"\u0002\u0005\u0007\u0005\u0002\u0006\u0007\u0006\u0002\u0007\u0007\u0007"+
		"\u0002\b\u0007\b\u0002\t\u0007\t\u0002\n\u0007\n\u0002\u000b\u0007\u000b"+
		"\u0002\f\u0007\f\u0002\r\u0007\r\u0002\u000e\u0007\u000e\u0002\u000f\u0007"+
		"\u000f\u0002\u0010\u0007\u0010\u0002\u0011\u0007\u0011\u0002\u0012\u0007"+
		"\u0012\u0002\u0013\u0007\u0013\u0002\u0014\u0007\u0014\u0001\u0000\u0001"+
		"\u0000\u0004\u0000-\b\u0000\u000b\u0000\f\u0000.\u0001\u0000\u0005\u0000"+
		"2\b\u0000\n\u0000\f\u00005\t\u0000\u0001\u0000\u0005\u00008\b\u0000\n"+
		"\u0000\f\u0000;\t\u0000\u0001\u0000\u0001\u0000\u0001\u0001\u0001\u0001"+
		"\u0001\u0002\u0001\u0002\u0001\u0002\u0001\u0002\u0001\u0002\u0003\u0002"+
		"F\b\u0002\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0004"+
		"\u0001\u0004\u0001\u0004\u0001\u0004\u0001\u0004\u0003\u0004Q\b\u0004"+
		"\u0001\u0005\u0001\u0005\u0001\u0005\u0001\u0006\u0001\u0006\u0001\u0007"+
		"\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0001\b\u0001\b\u0001"+
		"\b\u0001\b\u0001\b\u0001\b\u0003\bc\b\b\u0001\b\u0001\b\u0001\t\u0001"+
		"\t\u0001\n\u0001\n\u0003\nk\b\n\u0001\u000b\u0001\u000b\u0001\u000b\u0004"+
		"\u000bp\b\u000b\u000b\u000b\f\u000bq\u0004\u000bt\b\u000b\u000b\u000b"+
		"\f\u000bu\u0001\u000b\u0001\u000b\u0001\u000b\u0004\u000b{\b\u000b\u000b"+
		"\u000b\f\u000b|\u0004\u000b\u007f\b\u000b\u000b\u000b\f\u000b\u0080\u0005"+
		"\u000b\u0083\b\u000b\n\u000b\f\u000b\u0086\t\u000b\u0001\u000b\u0001\u000b"+
		"\u0001\f\u0001\f\u0001\r\u0001\r\u0001\u000e\u0001\u000e\u0001\u000f\u0001"+
		"\u000f\u0001\u000f\u0004\u000f\u0093\b\u000f\u000b\u000f\f\u000f\u0094"+
		"\u0004\u000f\u0097\b\u000f\u000b\u000f\f\u000f\u0098\u0001\u000f\u0001"+
		"\u000f\u0001\u0010\u0001\u0010\u0001\u0011\u0001\u0011\u0001\u0012\u0001"+
		"\u0012\u0001\u0013\u0001\u0013\u0001\u0014\u0001\u0014\u0001\u0014\u0000"+
		"\u0000\u0015\u0000\u0002\u0004\u0006\b\n\f\u000e\u0010\u0012\u0014\u0016"+
		"\u0018\u001a\u001c\u001e \"$&(\u0000\u0000\u00a5\u0000*\u0001\u0000\u0000"+
		"\u0000\u0002>\u0001\u0000\u0000\u0000\u0004E\u0001\u0000\u0000\u0000\u0006"+
		"G\u0001\u0000\u0000\u0000\bP\u0001\u0000\u0000\u0000\nR\u0001\u0000\u0000"+
		"\u0000\fU\u0001\u0000\u0000\u0000\u000eW\u0001\u0000\u0000\u0000\u0010"+
		"\\\u0001\u0000\u0000\u0000\u0012f\u0001\u0000\u0000\u0000\u0014j\u0001"+
		"\u0000\u0000\u0000\u0016l\u0001\u0000\u0000\u0000\u0018\u0089\u0001\u0000"+
		"\u0000\u0000\u001a\u008b\u0001\u0000\u0000\u0000\u001c\u008d\u0001\u0000"+
		"\u0000\u0000\u001e\u008f\u0001\u0000\u0000\u0000 \u009c\u0001\u0000\u0000"+
		"\u0000\"\u009e\u0001\u0000\u0000\u0000$\u00a0\u0001\u0000\u0000\u0000"+
		"&\u00a2\u0001\u0000\u0000\u0000(\u00a4\u0001\u0000\u0000\u0000*3\u0003"+
		"\u0004\u0002\u0000+-\u0005\u0002\u0000\u0000,+\u0001\u0000\u0000\u0000"+
		"-.\u0001\u0000\u0000\u0000.,\u0001\u0000\u0000\u0000./\u0001\u0000\u0000"+
		"\u0000/0\u0001\u0000\u0000\u000002\u0003\u0004\u0002\u00001,\u0001\u0000"+
		"\u0000\u000025\u0001\u0000\u0000\u000031\u0001\u0000\u0000\u000034\u0001"+
		"\u0000\u0000\u000049\u0001\u0000\u0000\u000053\u0001\u0000\u0000\u0000"+
		"68\u0005\u0002\u0000\u000076\u0001\u0000\u0000\u00008;\u0001\u0000\u0000"+
		"\u000097\u0001\u0000\u0000\u00009:\u0001\u0000\u0000\u0000:<\u0001\u0000"+
		"\u0000\u0000;9\u0001\u0000\u0000\u0000<=\u0005\u0000\u0000\u0001=\u0001"+
		"\u0001\u0000\u0000\u0000>?\u0005\u0003\u0000\u0000?\u0003\u0001\u0000"+
		"\u0000\u0000@F\u0003\u0002\u0001\u0000AF\u0003\u0006\u0003\u0000BF\u0003"+
		"\u0014\n\u0000CF\u0003&\u0013\u0000DF\u0003(\u0014\u0000E@\u0001\u0000"+
		"\u0000\u0000EA\u0001\u0000\u0000\u0000EB\u0001\u0000\u0000\u0000EC\u0001"+
		"\u0000\u0000\u0000ED\u0001\u0000\u0000\u0000F\u0005\u0001\u0000\u0000"+
		"\u0000GH\u0005\u0004\u0000\u0000HI\u0003\b\u0004\u0000IJ\u0005\u0014\u0000"+
		"\u0000J\u0007\u0001\u0000\u0000\u0000KQ\u0003\n\u0005\u0000LQ\u0003\f"+
		"\u0006\u0000MQ\u0003\u000e\u0007\u0000NQ\u0003\u0010\b\u0000OQ\u0003\u0012"+
		"\t\u0000PK\u0001\u0000\u0000\u0000PL\u0001\u0000\u0000\u0000PM\u0001\u0000"+
		"\u0000\u0000PN\u0001\u0000\u0000\u0000PO\u0001\u0000\u0000\u0000Q\t\u0001"+
		"\u0000\u0000\u0000RS\u0005\f\u0000\u0000ST\u0003$\u0012\u0000T\u000b\u0001"+
		"\u0000\u0000\u0000UV\u0005\u0013\u0000\u0000V\r\u0001\u0000\u0000\u0000"+
		"WX\u0005\r\u0000\u0000XY\u0003$\u0012\u0000YZ\u0005\f\u0000\u0000Z[\u0003"+
		"$\u0012\u0000[\u000f\u0001\u0000\u0000\u0000\\]\u0005\u000e\u0000\u0000"+
		"]^\u0005\u0011\u0000\u0000^_\u0005\u000f\u0000\u0000_b\u0005\u0011\u0000"+
		"\u0000`a\u0005\u000f\u0000\u0000ac\u0005\u0011\u0000\u0000b`\u0001\u0000"+
		"\u0000\u0000bc\u0001\u0000\u0000\u0000cd\u0001\u0000\u0000\u0000de\u0005"+
		"\u0010\u0000\u0000e\u0011\u0001\u0000\u0000\u0000fg\u0005\u0012\u0000"+
		"\u0000g\u0013\u0001\u0000\u0000\u0000hk\u0003\u0016\u000b\u0000ik\u0003"+
		"\u001e\u000f\u0000jh\u0001\u0000\u0000\u0000ji\u0001\u0000\u0000\u0000"+
		"k\u0015\u0001\u0000\u0000\u0000ls\u0003\u0018\f\u0000mo\u0003\u0004\u0002"+
		"\u0000np\u0005\u0002\u0000\u0000on\u0001\u0000\u0000\u0000pq\u0001\u0000"+
		"\u0000\u0000qo\u0001\u0000\u0000\u0000qr\u0001\u0000\u0000\u0000rt\u0001"+
		"\u0000\u0000\u0000sm\u0001\u0000\u0000\u0000tu\u0001\u0000\u0000\u0000"+
		"us\u0001\u0000\u0000\u0000uv\u0001\u0000\u0000\u0000v\u0084\u0001\u0000"+
		"\u0000\u0000w~\u0003\u001a\r\u0000xz\u0003\u0004\u0002\u0000y{\u0005\u0002"+
		"\u0000\u0000zy\u0001\u0000\u0000\u0000{|\u0001\u0000\u0000\u0000|z\u0001"+
		"\u0000\u0000\u0000|}\u0001\u0000\u0000\u0000}\u007f\u0001\u0000\u0000"+
		"\u0000~x\u0001\u0000\u0000\u0000\u007f\u0080\u0001\u0000\u0000\u0000\u0080"+
		"~\u0001\u0000\u0000\u0000\u0080\u0081\u0001\u0000\u0000\u0000\u0081\u0083"+
		"\u0001\u0000\u0000\u0000\u0082w\u0001\u0000\u0000\u0000\u0083\u0086\u0001"+
		"\u0000\u0000\u0000\u0084\u0082\u0001\u0000\u0000\u0000\u0084\u0085\u0001"+
		"\u0000\u0000\u0000\u0085\u0087\u0001\u0000\u0000\u0000\u0086\u0084\u0001"+
		"\u0000\u0000\u0000\u0087\u0088\u0003\u001c\u000e\u0000\u0088\u0017\u0001"+
		"\u0000\u0000\u0000\u0089\u008a\u0005\u0005\u0000\u0000\u008a\u0019\u0001"+
		"\u0000\u0000\u0000\u008b\u008c\u0005\u0006\u0000\u0000\u008c\u001b\u0001"+
		"\u0000\u0000\u0000\u008d\u008e\u0005\u0007\u0000\u0000\u008e\u001d\u0001"+
		"\u0000\u0000\u0000\u008f\u0096\u0003 \u0010\u0000\u0090\u0092\u0003\u0004"+
		"\u0002\u0000\u0091\u0093\u0005\u0002\u0000\u0000\u0092\u0091\u0001\u0000"+
		"\u0000\u0000\u0093\u0094\u0001\u0000\u0000\u0000\u0094\u0092\u0001\u0000"+
		"\u0000\u0000\u0094\u0095\u0001\u0000\u0000\u0000\u0095\u0097\u0001\u0000"+
		"\u0000\u0000\u0096\u0090\u0001\u0000\u0000\u0000\u0097\u0098\u0001\u0000"+
		"\u0000\u0000\u0098\u0096\u0001\u0000\u0000\u0000\u0098\u0099\u0001\u0000"+
		"\u0000\u0000\u0099\u009a\u0001\u0000\u0000\u0000\u009a\u009b\u0003\"\u0011"+
		"\u0000\u009b\u001f\u0001\u0000\u0000\u0000\u009c\u009d\u0005\b\u0000\u0000"+
		"\u009d!\u0001\u0000\u0000\u0000\u009e\u009f\u0005\t\u0000\u0000\u009f"+
		"#\u0001\u0000\u0000\u0000\u00a0\u00a1\u0005\u0015\u0000\u0000\u00a1%\u0001"+
		"\u0000\u0000\u0000\u00a2\u00a3\u0005\n\u0000\u0000\u00a3\'\u0001\u0000"+
		"\u0000\u0000\u00a4\u00a5\u0005\u000b\u0000\u0000\u00a5)\u0001\u0000\u0000"+
		"\u0000\u000e.39EPbjqu|\u0080\u0084\u0094\u0098";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}