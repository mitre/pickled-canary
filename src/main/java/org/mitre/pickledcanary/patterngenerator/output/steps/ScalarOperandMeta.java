
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.List;

import org.json.JSONObject;

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
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Represents a scalar operand choice for a wildcard in the output json.
 */
public class ScalarOperandMeta extends OperandMeta {

	final PatternExpression expression;

	/**
	 * Scalar operand type
	 * 
	 * @param mask      mask of an operand
	 * @param varId     variable ID (e.g. Q1) of the operand
	 * @param operandId the index of the operand in the instruction
	 */
	public ScalarOperandMeta(List<Integer> mask, String varId, int operandId, PatternExpression expression) {
		super(TypeOfOperand.Scalar, mask, varId, operandId);
		this.expression = expression;
	}

	public PatternExpression getExpression() {
		return this.expression;
	}

	private static PatternExpression getPatExp(OperandSymbol sym) {
		PatternExpression patexp = sym.getDefiningExpression();

		if (patexp == null) {
			TripleSymbol defSym = sym.getDefiningSymbol();
			if (defSym != null) {
				patexp = defSym.getPatternExpression();
			}
		}
		return patexp;
	}

	protected static JSONObject expressionToJson(PatternExpression expression) {
		JSONObject out = new JSONObject();

		if (expression instanceof BinaryExpression) {
			JSONObject children = new JSONObject();
			children.put("left", expressionToJson(((BinaryExpression) expression).getLeft()));
			children.put("right", expressionToJson(((BinaryExpression) expression).getRight()));
			out.put("children", children);

			if (expression instanceof PlusExpression) {
				out.put("op", "Add");
			} else if (expression instanceof SubExpression) {
				out.put("op", "Sub");
			} else if (expression instanceof MultExpression) {
				out.put("op", "Mult");
			} else if (expression instanceof LeftShiftExpression) {
				out.put("op", "LeftShift");
			} else if (expression instanceof RightShiftExpression) {
				out.put("op", "RightShift");
			} else if (expression instanceof AndExpression) {
				out.put("op", "And");
			} else if (expression instanceof OrExpression) {
				out.put("op", "Or");
			} else if (expression instanceof XorExpression) {
				out.put("op", "Xor");
			} else if (expression instanceof DivExpression) {
				out.put("op", "Div");
			} else {
				throw new RuntimeException("Unsupported BinaryExpression type encountered");
			}
		} else if (expression instanceof UnaryExpression) {
			out.put("child", expressionToJson(((UnaryExpression) expression).getUnary()));

			if (expression instanceof MinusExpression) {
				out.put("op", "Minus");
			} else if (expression instanceof NotExpression) {
				out.put("op", "Not");
			} else {
				throw new RuntimeException("Unsupported UnaryExpression type encountered");
			}
		} else if (expression instanceof StartInstructionValue) {
			out.put("op", "StartInstructionValue");
		} else if (expression instanceof ConstantValue) {

			out.put("op", "ConstantValue");
			try {
				out.put("value", expression.getValue(null));
			} catch (MemoryAccessException e) {
				// This should never happen
				throw new RuntimeException("Invalid memory access");
			}
		} else if (expression instanceof OperandValue) {
			OperandValue ov = (OperandValue) expression;
			OperandSymbol sym = ov.getConstructor().getOperand(ov.getIndex());
			PatternExpression patexp = getPatExp(sym);

			if (patexp == null) {
				out.put("op", "ConstantValue");
				out.put("value", 0);
			} else {

				int i = sym.getOffsetBase();
				int offset = 0;
				if (i < 0)
					offset = sym.getRelativeOffset();

				out.put("op", "OperandValue");
				out.put("offset", offset);
				out.put("child", expressionToJson(patexp));
			}
		} else if (expression instanceof TokenField) {
			TokenField tf = (TokenField) expression;

			JSONObject tf_out = new JSONObject();
			tf_out.put("bigendian", tf.isBigEndian());
			tf_out.put("signbit", tf.hasSignbit());
			tf_out.put("bitstart", tf.getBitStart());
			tf_out.put("bitend", tf.getBitEnd());
			tf_out.put("bytestart", tf.getByteStart());
			tf_out.put("byteend", tf.getByteEnd());
			tf_out.put("shift", tf.getShift());

			out.put("op", "TokenField");
			out.put("value", tf_out);

		} else if (expression instanceof ContextField) {
			ContextField tf = (ContextField) expression;

			JSONObject tf_out = new JSONObject();
//			tf_out.put("bigendian", tf..isBigEndian());
			tf_out.put("signbit", tf.hasSignbit());
			tf_out.put("bitstart", tf.getStartBit());
			tf_out.put("bitend", tf.getEndBit());
			tf_out.put("bytestart", tf.getByteStart());
			tf_out.put("byteend", tf.getByteEnd());
			tf_out.put("shift", tf.getShift());

			out.put("op", "ContextField");
			out.put("value", tf_out);

		} else if (expression instanceof EndInstructionValue) {
			out.put("op", "EndInstructionValue");
		} else {
			throw new RuntimeException("Unsupported Expression type encountered");
		}

		return out;
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();

		out.put("expression", expressionToJson(this.expression));
		return out;
	}
}
