// Copyright (C) 2024 The MITRE Corporation All Rights Reserved

parser grammar pc_grammar;

options {
	tokenVocab = pc_lexer;
}

prog: line (NEWLINE+ line)* NEWLINE* EOF;

comment: COMMENT;

line 
    : comment
    | pc_command
	| pc_block_command
    | instruction
	| meta;

pc_command: TICK pc_command_body EXIT_TICK;

pc_command_body
	: byte_match
	| byte_string
	| masked_byte
	| any_bytes
	| label;

byte_match: BYTE_PREFIX byte;
byte_string: BYTE_STRING;

masked_byte: MASKED_BYTE_PREFIX byte BYTE_PREFIX byte;

any_bytes: ANY_BYTES MIXED_NUMBER COMMA_SEPARATOR MIXED_NUMBER (COMMA_SEPARATOR MIXED_NUMBER)? CLOSE_BRACE;

label: LABEL;

pc_block_command
	: or_statement
	| negative_lookahead;

or_statement: start_or (line NEWLINE+)+ (middle_or (line NEWLINE+)+)* end_or;

start_or: START_OR;
middle_or: MIDDLE_OR;
end_or: END_OR;

negative_lookahead: start_negative_lookahead (line NEWLINE+)+ end_negative_lookahead;

start_negative_lookahead: START_NEGATIVE_LOOKAHEAD;
end_negative_lookahead: END_NEGATIVE_LOOKAHEAD;


byte: BYTE;

instruction: INSTRUCTION;

meta: META;