
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.search;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.mitre.pickledcanary.patterngenerator.output.steps.AnyByte;
import org.mitre.pickledcanary.patterngenerator.output.steps.Jmp;
import org.mitre.pickledcanary.patterngenerator.output.steps.Match;
import org.mitre.pickledcanary.patterngenerator.output.steps.SaveStart;
import org.mitre.pickledcanary.patterngenerator.output.steps.Split;
import org.mitre.pickledcanary.patterngenerator.output.steps.Step;
import org.mitre.pickledcanary.patterngenerator.output.utils.LookupTable;

public class Pattern {

	protected final List<Step> steps;
	protected final List<LookupTable> tables;

	public Pattern(List<Step> steps, List<LookupTable> tables) {
		this.steps = steps;
		this.tables = tables;
	}

	public static Pattern getDotStar() {
		List<Step> steps = new ArrayList<>();
		steps.add(new Split(3, 1));
		steps.add(new AnyByte());
		steps.add(new Jmp(0));

		return new Pattern(steps, new ArrayList<>());
	}

	public static Pattern getSaveStart() {
		List<Step> steps = new ArrayList<>();
		steps.add(new SaveStart());

		return new Pattern(steps, new ArrayList<>());
	}

	public static Pattern getMatch() {
		List<Step> steps = new ArrayList<>();
		steps.add(new Match());

		return new Pattern(steps, new ArrayList<>());
	}

	/**
	 * Add 'amount' to all the branch or jump targets when that target is greater
	 * than or equal to 'threshold'
	 * 
	 * @param amount
	 * @param threshold
	 */
	public void increment(int amount, int threshold) {
		this.steps.forEach((x) -> x.increment(amount, threshold));
	}

	/**
	 * Add 'amount' to all the branch or jump targets
	 * 
	 * @param amount
	 */
	public void increment(int amount) {
		this.increment(amount, 0);
	}

	/**
	 * Add the given other pattern to the start of this pattern, adjusting this
	 * pattern so all branches still point to the same step operations they did
	 * previously (e.g. update the indexes they point to account for where the
	 * original instruction moved to)
	 * 
	 * @param other
	 * @return this
	 */
	public Pattern prepend(Pattern other) {
		this.increment(other.steps.size());

		Collections.reverse(other.steps);
		for (Step s : other.steps) {
			this.steps.add(0, s);
		}

		return this;
	}

	/**
	 * Add the given other pattern to the end of this pattern, adjusting this
	 * pattern so all branches still point to the same step operations they did
	 * previously (e.g. update the indexes they point to account for where the
	 * original instruction moved to)
	 * 
	 * @param other
	 * @return this
	 */
	public Pattern append(Pattern other) {
		other.increment(this.steps.size());
		this.steps.addAll(other.steps);
		return this;
	}

	/**
	 * Adds a .* to the start of the pattern and adds instructions to record
	 * the start of the match and when the pattern has matched.
	 * @return this
	 */
	public Pattern wrap() {
		return this.prepend(
				Pattern.getDotStar()
						.append(Pattern.getSaveStart())
		).append(Pattern.getMatch());
	}

	@Override
	public String toString() {
		StringBuilder out = new StringBuilder("Pattern: \n\tSteps:");
		for (Step s : this.steps) {
			out.append("\n\t\t").append(s.toString());
		}

		return out.toString();
	}

}
