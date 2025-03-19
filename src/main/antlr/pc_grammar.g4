// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

parser grammar pc_grammar;

options {
	tokenVocab = pc_lexer;
}

prog: NEWLINE* line (NEWLINE+ line)* NEWLINE* EOF;

comment: COMMENT;

line:
	comment
	| pc_command
	| pc_block_command
	| instruction
	| meta;

// Context consumes the EXIT_TICK to exit its 'pushMode' so we can't have it expect an EXIT_TICK here too
pc_command: TICK ((pc_command_body EXIT_TICK) | context);

pc_command_body:
	byte_match
	| byte_string
	| masked_byte
	| any_bytes
	| label;

byte_match: BYTE_PREFIX byte;
byte_string: BYTE_STRING;

masked_byte: MASKED_BYTE_PREFIX byte BYTE_PREFIX byte;

any_bytes:
	ANY_BYTES MIXED_NUMBER COMMA_SEPARATOR MIXED_NUMBER (
		COMMA_SEPARATOR MIXED_NUMBER
	)? CLOSE_BRACE;

label: LABEL;

pc_block_command: or_statement | negative_lookahead;

or_statement:
	start_or (line NEWLINE+)+ (middle_or (line NEWLINE+)+)* end_or;

start_or: START_OR;
middle_or: MIDDLE_OR;
end_or: END_OR;

negative_lookahead:
	start_negative_lookahead (line NEWLINE+)+ end_negative_lookahead;

start_negative_lookahead: START_NEGATIVE_LOOKAHEAD;
end_negative_lookahead: END_NEGATIVE_LOOKAHEAD;

byte: BYTE;

instruction: INSTRUCTION;

meta: META;

context:
	CONTEXT_PREFIX CONTEXT_NEWLINE? context_entry WHITESPACE? (
		((SEMICOLON CONTEXT_NEWLINE?) | CONTEXT_NEWLINE) context_entry WHITESPACE?
	)* CONTEXT_NEWLINE? CONTEXT_END;

context_entry: CONTEXT_VALUE;