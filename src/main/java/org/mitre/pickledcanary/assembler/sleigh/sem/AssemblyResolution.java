/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.pickledcanary.assembler.sleigh.sem;

import java.util.*;

import org.mitre.pickledcanary.assembler.sleigh.expr.MaskedLong;

import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;

/**
 * The (often intermediate) result of assembly
 * 
 * <p>
 * These may represent a successful construction ({@link AssemblyResolvedPatterns}, a future field
 * ({@link AssemblyResolvedBackfill}), or an error ({@link AssemblyResolvedError}).
 * 
 * <p>
 * This class also provides the static factory methods for constructing any of its subclasses.
 */
public abstract class AssemblyResolution implements Comparable<AssemblyResolution> {
	protected final String description;
	protected final List<AssemblyResolution> children;
	protected final AssemblyResolution right;

	private boolean hashed = false;
	private int hash;
	
	// operand data tree
	protected AssemblyOperandData operandData = null;

	@Override
	public int hashCode() {
		if (!hashed) {
			hash = computeHash();
			hashed = true;
		}
		return hash;
	}

	protected abstract int computeHash();

	/**
	 * Construct a resolution
	 * 
	 * @param description a textual description used as part of {@link #toString()}
	 * @param children for record keeping, any children used in constructing this resolution
	 */
	AssemblyResolution(String description, List<? extends AssemblyResolution> children,
			AssemblyResolution right) {
		this.description = description;
		this.children = children == null ? List.of() : Collections.unmodifiableList(children);
		this.right = right;
	}

	/* ********************************************************************************************
	 * Static factory methods
	 */

	/**
	 * Build the result of successfully resolving a SLEIGH constructor
	 * 
	 * <p>
	 * <b>NOTE:</b> This is not used strictly for resolved SLEIGH constructors. It may also be used
	 * to store intermediates, e.g., encoded operands, during constructor resolution.
	 * 
	 * @param ins the instruction pattern block
	 * @param ctx the context pattern block
	 * @param description a description of the resolution
	 * @param cons the constructor, or null
	 * @param children the children of this constructor, or null
	 * @return the new resolution
	 */
	public static AssemblyResolvedPatterns resolved(AssemblyPatternBlock ins,
			AssemblyPatternBlock ctx, String description, Constructor cons,
			List<? extends AssemblyResolution> children, AssemblyResolution right) {
		return new AssemblyResolvedPatterns(description, cons, children, right, ins, ctx, null,
			null);
	}

	/**
	 * Build an instruction-only successful resolution result
	 * 
	 * @param ins the instruction pattern block
	 * @param description a description of the resolution
	 * @return the new resolution
	 * @see #resolved(AssemblyPatternBlock, AssemblyPatternBlock, String, Constructor, List, AssemblyResolution)
	 */
	public static AssemblyResolvedPatterns instrOnly(AssemblyPatternBlock ins,
			String description) {
		return resolved(ins, AssemblyPatternBlock.nop(), description, null, null, null);
	}

	/**
	 * Build a context-only successful resolution result
	 * 
	 * @param ctx the context pattern block
	 * @param description a description of the resolution
	 * @return the new resolution
	 * @see #resolved(AssemblyPatternBlock, AssemblyPatternBlock, String, Constructor, List, AssemblyResolution)
	 */
	public static AssemblyResolvedPatterns contextOnly(AssemblyPatternBlock ctx,
			String description) {
		return resolved(AssemblyPatternBlock.nop(), ctx, description, null, null, null);
	}

	/**
	 * Build a successful resolution result from a SLEIGH constructor's patterns
	 * 
	 * @param pat the constructor's pattern
	 * @param description a description of the resolution
	 * @return the new resolution
	 */
	public static AssemblyResolvedPatterns fromPattern(DisjointPattern pat, int minLen,
			String description, Constructor cons) {
		AssemblyPatternBlock ins = AssemblyPatternBlock.fromPattern(pat, minLen, false);
		AssemblyPatternBlock ctx = AssemblyPatternBlock.fromPattern(pat, 0, true);
		return resolved(ins, ctx, description, cons, null, null);
	}

	/**
	 * Build a backfill record to attach to a successful resolution result
	 * 
	 * @param exp the expression depending on a missing symbol
	 * @param goal the desired value of the expression
	 * @param inslen the length of instruction portion expected in the future solution
	 * @param description a description of the backfill record
	 * @return the new record
	 */
	public static AssemblyResolvedBackfill backfill(PatternExpression exp, MaskedLong goal,
			int inslen, String description) {
		return new AssemblyResolvedBackfill(description, exp, goal, inslen, 0);
	}

	/**
	 * Obtain a new "blank" resolved SLEIGH constructor record
	 * 
	 * @param description a description of the resolution
	 * @param children any children that will be involved in populating this record
	 * @return the new resolution
	 */
	public static AssemblyResolvedPatterns nop(String description,
			List<? extends AssemblyResolution> children, AssemblyResolution right) {
		return resolved(AssemblyPatternBlock.nop(), AssemblyPatternBlock.nop(), description, null,
			children, right);
	}

	/**
	 * Obtain a new "blank" resolved SLEIGH constructor record
	 * 
	 * @param description a description of the resolution
	 * @return the new resolution
	 */
	public static AssemblyResolvedPatterns nop(String description) {
		return resolved(AssemblyPatternBlock.nop(), AssemblyPatternBlock.nop(), description, null,
			null, null);
	}

	/**
	 * Build an error resolution record
	 * 
	 * @param error a description of the error
	 * @param description a description of what the resolver was doing when the error ocurred
	 * @param children any children involved in generating the error
	 * @return the new resolution
	 */
	public static AssemblyResolvedError error(String error, String description,
			List<? extends AssemblyResolution> children, AssemblyResolution right) {
		return new AssemblyResolvedError(description, children, right, error);
	}

	/**
	 * Build an error resolution record
	 * 
	 * @param error a description of the error
	 * @param description a description of what the resolver was doing when the error occurred
	 * @return the new resolution
	 */
	public static AssemblyResolvedError error(String error, String description) {
		return new AssemblyResolvedError(description, null, null, error);
	}

	/**
	 * Build an error resolution record, based on an intermediate SLEIGH constructor record
	 * 
	 * @param error a description of the error
	 * @param res the constructor record that was being populated when the error ocurred
	 * @return the new error resolution
	 */
	public static AssemblyResolution error(String error, AssemblyResolvedPatterns res) {
		return error(error, res.description, res.children, res.right);
	}

	/* ********************************************************************************************
	 * Abstract methods
	 */

	/**
	 * Check if this record describes an error
	 * 
	 * @return true if the record is an error
	 */
	public abstract boolean isError();

	/**
	 * Check if this record describes a backfill
	 * 
	 * @return true if the record is a backfill
	 */
	public abstract boolean isBackfill();

	/**
	 * Display the resolution result in one line (omitting child details)
	 * 
	 * @return the display description
	 */
	protected abstract String lineToString();

	/* ********************************************************************************************
	 * Misc
	 */

	protected List<AssemblyResolution> getAllRight() {
		List<AssemblyResolution> result = new ArrayList<>();
		collectAllRight(result);
		return result;
	}

	protected void collectAllRight(Collection<AssemblyResolution> into) {
		into.add(this);
		if (right == null) {
			return;
		}
		right.collectAllRight(into);
	}

	/**
	 * Get the child portion of {@link #toString()}
	 * 
	 * <p>
	 * If a subclass has another, possible additional, notion of children that it would like to
	 * include in {@link #toString()}, it must override this method.
	 * 
	 * @see #hasChildren()
	 * @param indent the current indentation
	 * @return the indented description for each child on its own line
	 */
	protected String childrenToString(String indent) {
		StringBuilder sb = new StringBuilder();
		for (AssemblyResolution child : children) {
			sb.append(child.toString(indent) + "\n");
		}
		return sb.substring(0, sb.length() - 1);
	}

	/**
	 * Used only by parents: get a multi-line description of this record, indented
	 * 
	 * @param indent the current indentation
	 * @return the indented description
	 */
	public String toString(String indent) {
		StringBuilder sb = new StringBuilder();
		sb.append(indent);
		sb.append(lineToString());
		if (hasChildren()) {
			sb.append(":\n");
			String newIndent = indent + "  ";
			sb.append(childrenToString(newIndent));
		}
		return sb.toString();
	}

	/**
	 * Describe this record including indented children, grandchildren, etc., each on its own line
	 */
	@Override
	public String toString() {
		return toString("");
	}

	@Override
	public int compareTo(AssemblyResolution that) {
		return this.toString().compareTo(that.toString()); // LAZY
	}

	/**
	 * Check if this record has children
	 * 
	 * <p>
	 * If a subclass has another, possibly additional, notion of children that it would like to
	 * include in {@link #toString()}, it must override this method to return true when such
	 * children are present.
	 * 
	 * @see #childrenToString(String)
	 * @return true if this record has children
	 */
	public boolean hasChildren() {
		if (children == null) {
			return false;
		}
		if (children.size() == 0) {
			return false;
		}
		return true;
	}

	/**
	 * Shift the resolution's instruction pattern to the right, if applicable
	 * 
	 * <p>
	 * This also shifts any backfill and forbidden pattern records.
	 * 
	 * @param amt the number of bytes to shift.
	 * @return the result
	 */
	public abstract AssemblyResolution shift(int amt);

	/**
	 * Get this same resolution, but without any right siblings
	 * 
	 * @return the resolution
	 */
	public AssemblyResolution withoutRight() {
		return withRight(null);
	}

	/**
	 * Get this same resolution, but with the given right sibling
	 * 
	 * @return the resolution
	 */
	public abstract AssemblyResolution withRight(AssemblyResolution right);

	/**
	 * Get this same resolution, pushing its right siblings down to its children
	 */
	public abstract AssemblyResolution parent(String description, int opCount);

	public void setOperandData(AssemblyOperandData operandData) {
		this.operandData = operandData;
	}

	public AssemblyOperandData getOperandData() {
		return operandData;
	}

	// for debug
	public void printOperandData() {
		if (operandData != null) {
			System.out.println(operandData);
		}
		for (AssemblyResolution ar : children) {
			ar.printOperandData();
		}
	}
}
