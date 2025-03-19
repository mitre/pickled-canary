// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

lexer grammar pc_lexer;

NEWLINE: [ \t]* [\r\n]+;

COMMENT: ' '* ';' ' '? ~[\r\n]*;

TICK: ' '* '`' -> pushMode(PC_COMMAND_BODY_MODE);

START_OR:
	' '* '`' ' '* ('START_OR' | 'OR_START') ' '* '{'? ' '* '`' ' '* [\n\r]+;
MIDDLE_OR:
	' '* '`' ' '* '}'? ' '* 'OR' ' '* '{'? ' '* '`' ' '* [\n\r]+;
END_OR:
	' '* '`' ' '* '}'? ' '* ('END_OR' | 'OR_END') ' '* '`' ' '*;

START_NEGATIVE_LOOKAHEAD:
	' '* '`' ' '* 'NOT' ' '* '{'? ' '* '`' ' '* [\n\r]+;
END_NEGATIVE_LOOKAHEAD:
	' '* '`' ' '* '}'? ' '* ('END_NOT' | 'NOT_END') ' '* '`' ' '*;

// Instructions don't start with a tick (unless it's an escaped double tick)
INSTRUCTION:
	' '* ('``' | ~('`' | '\r' | '\n' | ' ')) ~('\n' | '\r')+;

META:
	' '* '`META`' [\r\n]+ .*? [\r\n]+ ' '* (
		'`META_END`'
		| '`END_META`'
		| '`META`'
	);

mode PC_COMMAND_BODY_MODE;

BYTE_PREFIX: '=' -> pushMode(BYTE_MODE);

MASKED_BYTE_PREFIX: '&' -> pushMode(BYTE_MODE);

ANY_BYTES: 'ANY_BYTES' ' '* '{' ' '*;
COMMA_SEPARATOR: ' '* ',' ' '*;
CLOSE_BRACE: '}';

CONTEXT_PREFIX: 'CONTEXT' -> pushMode(CONTEXT_MODE);

MIXED_NUMBER: ( '0x' [0-9a-fA-F]+) | [0-9]+;

LABEL: [a-zA-Z] [a-zA-Z0-9_]* ':' ' '*;

BYTE_STRING: '"' ( '\\"' | '\\\\' | ~["\\\n\r])*? '"';

// PC_COMMAND_BODY:   ( '``' | ~[`\r\n] )+  ;

EXIT_TICK: '`' -> popMode;

mode BYTE_MODE;

BYTE: '0x' [0-9a-fA-F][0-9a-fA-F]? -> popMode;

mode CONTEXT_MODE;

CONTEXT_VALUE:
	[ \t]* [A-Za-z0-9_]+ ' '* '=' ' '* (
		('0x' [0-9a-fA-F]+)
		| [0-9]+
		| '0b' [01]+
		| (["'] [0-9a-fA-FxX .[\]]+ ["'])
	);
CONTEXT_NEWLINE: [ \t]* [\n\r]+;
WHITESPACE: [ \t]+;
SEMICOLON: ';';
CONTEXT_END: '`' -> popMode, popMode;