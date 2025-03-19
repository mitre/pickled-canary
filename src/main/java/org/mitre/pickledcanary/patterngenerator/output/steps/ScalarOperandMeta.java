
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.List;
import java.util.Objects;

import org.json.JSONObject;
import org.mitre.pickledcanary.patterngenerator.ExpressionMemoryAccessException;
import org.mitre.pickledcanary.patterngenerator.UnsupportedExpressionException;

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

	public static final String JSON_KEY_OP = "op";
	public static final String JSON_KEY_VALUE = "value";
	public static final String JSON_KEY_LEFT = "left";
	public static final String JSON_KEY_RIGHT = "right";
	public static final String JSON_KEY_CHILD = "child";
	public static final String JSON_KEY_CHILDREN = "children";
	private static final String JSON_KEY_OFFSET = "offset";

	final PatternExpression expression;

	/**
	 * Scalar operand type
	 *
	 * @param mask      mask of an operand
	 * @param varId     variable ID (e.g. Q1) of the operand
	 */
	public ScalarOperandMeta(List<Integer> mask, String varId, PatternExpression expression) {
		super(TypeOfOperand.Scalar, mask, varId);
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
		if (expression instanceof BinaryExpression binaryExpression) {
			return binaryExpressionToJson(binaryExpression);
		} else if (expression instanceof UnaryExpression unaryExpression) {
			return unaryExpressionToJson(unaryExpression);
		} else if (expression instanceof StartInstructionValue) {
			return startInstructionValueToJson();
		} else if (expression instanceof ConstantValue constantValue) {
			return constantValueToJson(constantValue);
		} else if (expression instanceof OperandValue operandValue) {
			return operandValueToJson(operandValue);
		} else if (expression instanceof TokenField tokenField) {
			return tokenFieldToJson(tokenField);
		} else if (expression instanceof ContextField contextField) {
			return contextFieldToJson(contextField);
		} else if (expression instanceof EndInstructionValue) {
			return endInstructionValueToJson();
		} else {
			throw new UnsupportedExpressionException(expression);
		}
	}

	private static JSONObject endInstructionValueToJson() {
		JSONObject out = new JSONObject();
		out.put("op", "EndInstructionValue");
		return out;
	}

	protected static JSONObject contextFieldToJson(ContextField tf) {
		JSONObject out = new JSONObject();

		JSONObject tfOut = new JSONObject();
		//	not adding bigEndian to contextField ops anymore
		tfOut.put("signbit", tf.hasSignbit());
		tfOut.put("bitstart", tf.getStartBit());
		tfOut.put("bitend", tf.getEndBit());
		tfOut.put("bytestart", tf.getByteStart());
		tfOut.put("byteend", tf.getByteEnd());
		tfOut.put("shift", tf.getShift());

		out.put(JSON_KEY_OP, "ContextField");
		out.put(JSON_KEY_VALUE, tfOut);
		return out;
	}

	protected static JSONObject tokenFieldToJson(TokenField tf) {
		JSONObject out = new JSONObject();

		JSONObject tfOut = new JSONObject();
		tfOut.put("bigendian", tf.isBigEndian());
		tfOut.put("signbit", tf.hasSignbit());
		tfOut.put("bitstart", tf.getBitStart());
		tfOut.put("bitend", tf.getBitEnd());
		tfOut.put("bytestart", tf.getByteStart());
		tfOut.put("byteend", tf.getByteEnd());
		tfOut.put("shift", tf.getShift());

		out.put(JSON_KEY_OP, "TokenField");
		out.put(JSON_KEY_VALUE, tfOut);
		return out;
	}

	protected static JSONObject operandValueToJson(OperandValue ov) {
		JSONObject out = new JSONObject();
		OperandSymbol sym = ov.getConstructor().getOperand(ov.getIndex());
		PatternExpression patexp = getPatExp(sym);

		if (patexp == null) {
			out.put(JSON_KEY_OP, "ConstantValue");
			out.put(JSON_KEY_VALUE, 0);
		} else {
			int i = sym.getOffsetBase();
			int offset = 0;
			if (i < 0) {
				offset = sym.getRelativeOffset();
			}

			out.put(JSON_KEY_OP, "OperandValue");
			out.put(JSON_KEY_OFFSET, offset);
			out.put(JSON_KEY_CHILD, expressionToJson(patexp));
		}

		return out;
	}

	protected static JSONObject constantValueToJson(ConstantValue constantValue) {
		JSONObject out = new JSONObject();
		out.put(JSON_KEY_OP, "ConstantValue");
		try {
			out.put(JSON_KEY_VALUE, constantValue.getValue(null));
		} catch (MemoryAccessException e) {
			// This should never happen
			throw new ExpressionMemoryAccessException(constantValue, e);
		}
		return out;
	}

	protected static JSONObject startInstructionValueToJson() {
		JSONObject out = new JSONObject();
		out.put(JSON_KEY_OP, "StartInstructionValue");
		return out;
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();

		out.put("expression", expressionToJson(this.expression));
		return out;
	}

	protected static JSONObject binaryExpressionToJson(BinaryExpression binary) {
		JSONObject out = new JSONObject();

		JSONObject children = new JSONObject();
		children.put(JSON_KEY_LEFT, expressionToJson(binary.getLeft()));
		children.put(JSON_KEY_RIGHT, expressionToJson(binary.getRight()));
		out.put(JSON_KEY_CHILDREN, children);

		if (binary instanceof PlusExpression) {
			out.put(JSON_KEY_OP, "Add");
		} else if (binary instanceof SubExpression) {
			out.put(JSON_KEY_OP, "Sub");
		} else if (binary instanceof MultExpression) {
			out.put(JSON_KEY_OP, "Mult");
		} else if (binary instanceof LeftShiftExpression) {
			out.put(JSON_KEY_OP, "LeftShift");
		} else if (binary instanceof RightShiftExpression) {
			out.put(JSON_KEY_OP, "RightShift");
		} else if (binary instanceof AndExpression) {
			out.put(JSON_KEY_OP, "And");
		} else if (binary instanceof OrExpression) {
			out.put(JSON_KEY_OP, "Or");
		} else if (binary instanceof XorExpression) {
			out.put(JSON_KEY_OP, "Xor");
		} else if (binary instanceof DivExpression) {
			out.put(JSON_KEY_OP, "Div");
		} else {
			throw new UnsupportedExpressionException(binary);
		}

		return out;
	}

	protected static JSONObject unaryExpressionToJson(UnaryExpression unary) {
		JSONObject out = new JSONObject();
		out.put(JSON_KEY_CHILD, expressionToJson(unary.getUnary()));

		if (unary instanceof MinusExpression) {
			out.put(JSON_KEY_OP, "Minus");
		} else if (unary instanceof NotExpression) {
			out.put(JSON_KEY_OP, "Not");
		} else {
			throw new UnsupportedExpressionException(unary);
		}

		return out;
	}

	public boolean hasContext() {
		return walkExpression(this.expression);
	}

	// Detect if at least one ContextField exists in expression
	// TODO: Is there a decent way to make this logic reusable?
	// It's very similar to expressionToJson()
	protected boolean walkExpression(PatternExpression expression) {
		if (expression instanceof BinaryExpression binaryExpression) {
			return walkBinaryExpression(binaryExpression);
		} else if (expression instanceof UnaryExpression unaryExpression) {
			return walkUnaryExpression(unaryExpression);
		} else if (expression instanceof OperandValue operandValue) {
			return walkOperandValueExpression(operandValue);
		} else if (expression instanceof ContextField) {
			return true;
		}
		return false;
	}

	protected boolean walkBinaryExpression(BinaryExpression expression) {
		if (walkExpression(expression.getLeft()) || walkExpression(expression.getRight())) {
			return true;
		}
		return false;
	}

	protected boolean walkUnaryExpression(UnaryExpression expression) {
		if (walkExpression(expression.getUnary())) {
			return true;
		}
		return false;
	}

	protected boolean walkOperandValueExpression(OperandValue operandValue) {
		OperandSymbol sym = operandValue.getConstructor().getOperand(operandValue.getIndex());
		PatternExpression patexp = sym.getDefiningExpression();
		if (patexp == null) {
			TripleSymbol defSym = sym.getDefiningSymbol();
			if (defSym != null) {
				patexp = defSym.getPatternExpression();
			}
			if (patexp == null) {
				return false;
			}
		}
		if (walkExpression(patexp)) {
			return true;
		}
		return false;
	}

	// TODO: PatternExpression doesn't implement hashCode or equals method, so this may not work
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Objects.hash(expression);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj) || getClass() != obj.getClass()) {
			return false;
		}
		ScalarOperandMeta other = (ScalarOperandMeta) obj;
		return Objects.equals(expression, other.expression);
	}
}
