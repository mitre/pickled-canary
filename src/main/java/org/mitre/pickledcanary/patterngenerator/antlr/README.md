# Pickled Canary Lexer/Parser

This directory contains the files needed to generate the "generated" folder at
the same level as this folder.

# Building

Before you build, make sure Antlr4-tools is installed and on your path. See
https://antlr.org for instructions.

In this directory:
```bash
antlr4 -o ../generated -visitor pc_grammar.g4 pc_lexer.g4
```

# Debugging

For lots of details about debugging see https://antlr.org.

## Lexer 
To test changes to the lexer, create a file "test.ptn" in this directory with
the pattern you'd like to try lexing, then:
```bash
antlr4-parse pc_grammar.g4 pc_lexer.g4 prog -tokens -diagnostics test.ptn
```

## Parser
To test changes to the parser, create a file "test.ptn" in this directory with
the pattern you'd like to try parsing, then:
```bash
antlr4-parse pc_grammar.g4 pc_lexer.g4 prog -gui test.ptn
```
