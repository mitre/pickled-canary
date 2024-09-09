
// Copyright (C) 2024 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import ghidra.app.plugin.processors.sleigh.expression.AndExpression;
import ghidra.app.plugin.processors.sleigh.expression.BinaryExpression;
import ghidra.app.plugin.processors.sleigh.expression.ConstantValue;
import ghidra.app.plugin.processors.sleigh.expression.ContextField;
import ghidra.app.plugin.processors.sleigh.expression.DivExpression;
import ghidra.app.plugin.processors.sleigh.expression.EndInstructionValue;
import ghidra.app.plugin.processors.sleigh.expression.LeftShiftExpression;
import ghidra.app.plugin.processors.sleigh.expression.MinusExpression;
import ghidra.app.plugin.processors.sleigh.expression.MultExpression;
import ghidra.app.plugin.processors.sleigh.expression.NotExpression;
import ghidra.app.plugin.processors.sleigh.expression.OperandValue;
import ghidra.app.plugin.processors.sleigh.expression.OrExpression;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.expression.PlusExpression;
import ghidra.app.plugin.processors.sleigh.expression.RightShiftExpression;
import ghidra.app.plugin.processors.sleigh.expression.StartInstructionValue;
import ghidra.app.plugin.processors.sleigh.expression.SubExpression;
import ghidra.app.plugin.processors.sleigh.expression.TokenField;
import ghidra.app.plugin.processors.sleigh.expression.UnaryExpression;
import ghidra.app.plugin.processors.sleigh.expression.XorExpression;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;
import ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import org.mitre.pickledcanary.patterngenerator.ExpressionMemoryAccessException;
import org.mitre.pickledcanary.patterngenerator.UnsupportedExpressionException;

/**
 * Ghidra already has a built-in expression solver (accessed by calling
 * "getValue" on an expression), however it wants a "ParserWalker" which itself
 * wants a context. This is a problem for us as we don't directly have either of
 * these. I attempted to extend the required classes to make my own
 * Walker/Context, however this doesn't work because some expression statements
 * create new Walkers from the one you originally gave it (and these are not our
 * new class). So... I believe I've extracted (and modified) the necessary bits
 * of the Walker, context, and getValue logic from various places into this
 * class. This being said, what I've done is probably not the *right* way, but
 * it's a way which works without further modification of core Ghidra code.
 */
public class LookupDataExpressionSolver {
	private LookupDataExpressionSolver() {
		// Utility class, no constructor.
	}

	/**
	 * More or less like "getValue(Walker)" on an expression, but without the need
	 * for a Walker.
	 * <p>
	 * Compare with what occurs in the various PatternExpression.getValue
	 * implementations.
	 */
	public static long computeExpression(PatternExpression expression, MemBuffer input, int sp, int len) {
		if (expression instanceof BinaryExpression binaryExpression) {
			return computeBinaryExpression(binaryExpression, input, sp, len);
		} else if (expression instanceof UnaryExpression unaryExpression) {
			return computeUnaryExpression(unaryExpression, input, sp, len);
		} else if (expression instanceof StartInstructionValue) {
			return input.getAddress().add(sp).getUnsignedOffset();
		} else if (expression instanceof ConstantValue constantValue) {
			return computeConstantExpression(constantValue);
		} else if (expression instanceof OperandValue ov) {
			return computeOperandValueExpression(ov, input, sp, len);
		} else if (expression instanceof TokenField tf) {
			return computeTokenFieldExpression(tf, input, sp);
		} else if (expression instanceof ContextField tf) {
			return computeContextFieldExpression(tf, input, sp);
		} else if (expression instanceof EndInstructionValue) {
			return computeEndInstructionValueExpression(input, sp, len);
		} else {
			throw new UnsupportedExpressionException(expression);
		}
	}

	/**
	 * Get size bytes at offset into input and return as a long.
	 * <p>
	 * Bad things will happen if size is more bytes than can be held in a long and
	 * the memory being read from those bytes has a non-zero value.
	 * <p>
	 * Compare with "getInstructionBytes" in ghidra.app.plugin.processors.sleigh
	 */
	private static long getBytes(MemBuffer input, int offset, int size) throws MemoryAccessException {
		byte[] bytes = new byte[size]; // leave any unavailable bytes as 0 in result
		int readSize = input.getBytes(bytes, offset);
		if (offset == 0 && readSize == 0) {
			throw new MemoryAccessException("Invalid memory access");
		}
		int result = 0;
		for (int i = 0; i < size; i++) {
			result <<= 8;
			result |= bytes[i] & 0xff;
		}
		return result;
	}

	/**
	 * Get the bytes which make up the instruction defined by tf assuming tf is at
	 * offset sp into input. Return the results as a long.
	 * <p>
	 * This will probably go bad if an instruction has more bytes than fit into a
	 * long.
	 * <p>
	 * Compare with "getInstructionBytes" in
	 * ghidra.app.plugin.processors.sleigh.expression.TokenField
	 */
	private static long getInstructionBytes(TokenField tf, MemBuffer input, int sp) throws MemoryAccessException {
		long res = 0;
		int bs = tf.getByteStart();
		int size = tf.getByteEnd() - tf.getByteStart() + 1;
		int tmpsize = size;

		while (tmpsize >= 4) {
			long tmp = input.getInt(sp + bs);
			res = res << 32;
			res |= (tmp & 0xffffffffL);
			bs += 4;
			tmpsize -= 4;
		}
		if (tmpsize > 0) {
			long tmp = getBytes(input, sp + bs, tmpsize);
			res = res << (8 * tmpsize);
			res |= (tmp & 0xffffffffL);
		}
		if (!tf.isBigEndian())
			res = TokenField.byteSwap(res, size);
		return res;
	}

	/**
	 * Get bytes
	 * </p>
	 * Compare with "getContextBytes" in
	 * ghidra.app.plugin.processors.sleigh.expression.ContextField
	 */
	private static long getContextBytes(ContextField cf, MemBuffer input, int sp) throws MemoryAccessException {
		long res = 0;
		int tmp;
		int size;
		int bs = cf.getByteStart();

		size = cf.getByteEnd() - bs + 1;
		while (size >= 4) {
			tmp = input.getInt(sp + bs);
			res <<= 32;
			res |= tmp;
			bs += 4;
			size = cf.getByteEnd() - bs + 1;
		}
		if (size > 0) {
			tmp = input.getInt(sp + bs);
			res <<= 8 * size;
			res |= tmp;
		}
		return res;
	}

	private static long computeContextFieldExpression(ContextField tf, MemBuffer input, int sp) {
		// This seems to be almost the same thing as a TokenField... what's actually the
		// difference?
		// TODO: is this implemented correctly? Should we be reading something else
		// here?
		long res;
		try {
			res = getContextBytes(tf, input, sp);
		} catch (MemoryAccessException e) {
			throw new ExpressionMemoryAccessException(tf, e);
		}

		res >>= tf.getShift();
		if (tf.hasSignbit())
			res = TokenField.signExtend(res, tf.getEndBit() - tf.getStartBit());
		else
			res = TokenField.zeroExtend(res, tf.getEndBit() - tf.getStartBit());
		return res;
	}

	private static long computeTokenFieldExpression(TokenField tf, MemBuffer input, int sp) {
		long res;
		try {
			res = getInstructionBytes(tf, input, sp);
		}
		catch (MemoryAccessException e) {
			throw new ExpressionMemoryAccessException(tf, e);
		}

		res >>= tf.getShift();
		if (tf.hasSignbit()) {
			return TokenField.signExtend(res, tf.getBitEnd() - tf.getBitStart());
		}

		return TokenField.zeroExtend(res, tf.getBitEnd() - tf.getBitStart());

	}

	private static long computeOperandValueExpression(OperandValue ov, MemBuffer input, int sp, int len) {
		OperandSymbol sym = ov.getConstructor().getOperand(ov.getIndex());
		PatternExpression patexp = sym.getDefiningExpression();
		if (patexp == null) {
			TripleSymbol defSym = sym.getDefiningSymbol();
			if (defSym != null) {
				patexp = defSym.getPatternExpression();
			}
			if (patexp == null) {
				return 0;
			}
		}

		int i = sym.getOffsetBase();
		int offset = 0;
		if (i < 0)
			offset = sym.getRelativeOffset();

		// TODO: Should len be adjusted here? Probably... See other stuff done in
		// ParserWalker.setOutOfBandState
		return computeExpression(patexp, input, sp + offset, len);
	}

	private static long computeConstantExpression(ConstantValue expression) {
		try {
			return expression.getValue(null);
		} catch (MemoryAccessException e) {
			// This should never happen
			throw new ExpressionMemoryAccessException(expression, e);
		}
	}

	private static long computeBinaryExpression(BinaryExpression expression, MemBuffer input, int sp, int len) {
		long leftval = computeExpression(expression.getLeft(), input, sp, len);
		long rightval = computeExpression(expression.getRight(), input, sp, len);
		
		if (expression instanceof PlusExpression) {
			return leftval + rightval;
		} else if (expression instanceof SubExpression) {
			return leftval - rightval;
		} else if (expression instanceof MultExpression) {
			return leftval * rightval;
		} else if (expression instanceof LeftShiftExpression) {
			return leftval << rightval;
		} else if (expression instanceof RightShiftExpression) {
			return leftval >> rightval;
		} else if (expression instanceof AndExpression) {
			return leftval & rightval;
		} else if (expression instanceof OrExpression) {
			return leftval | rightval;
		} else if (expression instanceof XorExpression) {
			return leftval ^ rightval;
		} else if (expression instanceof DivExpression) {
			return leftval / rightval;
		} else {
			throw new UnsupportedExpressionException(expression);
		}
	}
	
	private static long computeUnaryExpression(UnaryExpression expression, MemBuffer input, int sp, int len) {
		long unary = computeExpression(expression.getUnary(), input, sp, len);
		if (expression instanceof MinusExpression) {
			return -unary;
		} else if (expression instanceof NotExpression) {
			return ~unary;
		} else {
			throw new UnsupportedExpressionException(expression);
		}
	}

	private static long computeEndInstructionValueExpression(MemBuffer input, int sp, int len) {
		return input.getAddress().add((long) sp + len).getUnsignedOffset();
	}
}
