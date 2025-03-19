// Copyright (C) 2025 The MITRE Corporation All Rights Reserved
package org.mitre.pickledcanary.patterngenerator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;

import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.patterngenerator.PCVisitor.PatternContext;
import org.mitre.pickledcanary.patterngenerator.output.steps.Jmp;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupStep;
import org.mitre.pickledcanary.patterngenerator.output.steps.Split;
import org.mitre.pickledcanary.patterngenerator.output.steps.SplitMulti;
import org.mitre.pickledcanary.patterngenerator.output.steps.Step;
import org.mitre.pickledcanary.patterngenerator.output.steps.Step.StepType;

/**
 * After the pattern is passed through the second visitor to make the pattern context aware,
 * the pattern may have several duplicate branches. This third step removes all duplicate
 * branches.
 */
public class PathDeduplicator {

	private class InstructionNode {
		private Step step; // the instruction of the node
		private ArrayList<InstructionNode> children; // instructions that can be executed after current instruction

		// used for deduplication
		private int newStepsIdx; // the index of this node in the deduplicated list of steps
		private boolean doJump; // true if next step is duplicate

		/**
		 * Represents a node in the deduplication tree.
		 * @param step an instruction to execute
		 */
		private InstructionNode(Step step) {
			this.step = step;
			children = new ArrayList<>();
			doJump = false;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = prime + Objects.hash(step, children);
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null || getClass() != obj.getClass()) {
				return false;
			}
			InstructionNode other = (InstructionNode) obj;
			return Objects.equals(step, other.step) &&
				Objects.equals(children, other.children);
		}
	}

	/**
	 * Remove duplicate branches in the pattern.
	 *
	 * Steps to deduplicate:
	 * 1. Generate a tree out of all the steps in the pattern where each node is an instruction
	 * to execute. The children of each node are the next steps that can be executed.
	 * 2. When generating the tree, sometimes a next step can get added to the children more
	 * than once, so remove all duplicate next steps. We now have a directed acyclic graph.
	 * 3. The hash code of each node represents the content of the current step and all child
	 * steps down to the leaves. This makes up a branch. In the third step, duplicate branches
	 * are removed by traversing each node and ignoring branches that have already been seen.
	 * @param inputContext the input pattern
	 * @return deduplicated pattern
	 */
	public PatternContext deduplicatePaths(PatternContext inputContext) {
		// tree must have a root, so we add a filler step; otherwise, if pattern starts with OR
		// block, there will not be a root of the tree
		InstructionNode root = new InstructionNode(new LookupStep("ROOT", -1, -1));
		generateTree(0, root, inputContext.getSteps());
		removeDuplicateChildren(root);
		combineEncodingsWithEqualBranches(root);
		if (PickledCanary.DEBUG) {
			System.out.println("Deduplication tree:");
			printTree(0, root);
		}
		ArrayList<Step> newSteps = deduplicateTree(root);
		return new PatternContext(newSteps, inputContext.getTables());
	}

	/**
	 * Generates the DAG from the list of steps to allow for deduplication. Splits and jumps
	 * are removed, and the step that is split or jumped to is placed in the children field.
	 * @param idx current step to process
	 * @param parent the previous step
	 * @param steps all the steps in the pattern
	 */
	private void generateTree(int idx, InstructionNode parent, List<Step> steps) {
		if (idx >= steps.size()) {
			// we've reached the end of a branch; no more steps to process on this branch
			return;
		}
		Step step = steps.get(idx);
		switch (step.getStepType()) {
			// for splits or jumps, just go to the next step(s)
			case SPLITMULTI:
				SplitMulti splitMulti = (SplitMulti) step;
				for (int dest : splitMulti.getDests()) {
					generateTree(dest, parent, steps);
				}
				break;
			case JMP:
				generateTree(((Jmp) step).getDest(), parent, steps);
				break;
			default:
				// for all other steps, add a node to the tree and go to the next step
				InstructionNode node = new InstructionNode(steps.get(idx));
				generateTree(idx + 1, node, steps);
				parent.children.add(node);
		}
	}

	/**
	 * Remove children under a node that are the same.
	 * @param node node to check for similar children
	 */
	private void removeDuplicateChildren(InstructionNode node) {
		LinkedHashSet<InstructionNode> set = new LinkedHashSet<>(node.children);
		node.children.clear();
		node.children.addAll(set);
		for (InstructionNode child : node.children) {
			removeDuplicateChildren(child);
		}
	}

	/**
	 * An instruction that produces encodings with different output contexts will cause a split
	 * in the pattern, and each of the encodings with a different output context will be placed
	 * as the first instruction after the split. Sometimes, the rest of the branches will be
	 * equal, and therefore, the rest of the branches can be deduplicated, and the encodings in
	 * the separate output context steps can be combined back together.
	 *
	 * Two siblings with the same instruction text and the same children can be deduplicated.
	 * Therefore, deduplication is done by:
	 * 1) tracking siblings that meet the definition for deduplication
	 * 2) copying all encodings of all siblings into the first sibling
	 * 3) remove all siblings except the first from the parent's children list
	 * @param node node to combine instruction encodings with equal branches
	 */
	private void combineEncodingsWithEqualBranches(InstructionNode node) {
		// this hashmap tracks siblings with the same instruction text and children
		// instruction text          node's children      equal siblings indexes
		HashMap<String, HashMap<ArrayList<InstructionNode>, ArrayList<Integer>>> deduplicationTracker = new HashMap<>();
		for (int i = 0; i < node.children.size(); i++) {
			// this loop puts all siblings that meet the definition for deduplication in a group
			InstructionNode child = node.children.get(i);
			combineEncodingsWithEqualBranches(child);
			if (child.step.getStepType() != StepType.LOOKUP) {
				continue;
			}
			LookupStep step = (LookupStep) child.step;
			if (!deduplicationTracker.containsKey(step.getInstructionText())) {
				deduplicationTracker.put(step.getInstructionText(), new HashMap<>());
			}
			if (!deduplicationTracker.get(step.getInstructionText()).containsKey(child.children)) {
				deduplicationTracker.get(step.getInstructionText()).put(child.children, new ArrayList<>());
			}
			// group siblings by instruction text and siblings' children
			deduplicationTracker.get(step.getInstructionText()).get(child.children).add(i);
		}

		for (HashMap<ArrayList<InstructionNode>, ArrayList<Integer>> duplicateChildren : deduplicationTracker.values()) {
			for (ArrayList<Integer> combinableBranches : duplicateChildren.values()) {
				if (combinableBranches.size() < 2) {
					// if there's only 1 sibling in a group, no need to deduplicate
					continue;
				}

				// take the first sibling, add all encodings of the other siblings to first
				// sibling, then remove the other siblings
				Collections.sort(combinableBranches, Collections.reverseOrder());
				// TODO: replace remove with removeLast() when we have full JDK21 support
				InstructionNode branchToKeep = node.children.get(combinableBranches.remove(combinableBranches.size() - 1));
				LookupStep branchToKeepLookupStep = (LookupStep) branchToKeep.step;
				for (int idx : combinableBranches) {
					InstructionNode branchToCombine = node.children.get(idx);
					LookupStep branchToCombineLookupStep = (LookupStep) branchToCombine.step;
					branchToKeepLookupStep.combine(branchToCombineLookupStep);
					node.children.remove(idx);
				}
			}
		}
	}

	/**
	 * Prints out a tree.
	 * @param indent depth of indent to insert before printing a line
	 * @param node the tree to print
	 */
	private void printTree(int indent, InstructionNode node) {
		System.out.println("    ".repeat(indent) +  ": " + node.step.toString());
		for (InstructionNode child : node.children) {
			printTree(indent + 1, child);
		}
	}

	/**
	 * Remove branches that are the same by traversing through each node and ignoring branches
	 * that we have already seen.
	 * @param root the DAG to deduplicate
	 * @return a deduplicated list of steps
	 */
	private ArrayList<Step> deduplicateTree(InstructionNode root) {
		HashMap<InstructionNode, Integer> hashToIdx = new HashMap<>();
		ArrayList<Step> newSteps = new ArrayList<>();
		deduplicateTree(root, newSteps, hashToIdx); // the actual deduplication happens here
		// TODO: replace with removeFirst() when we have full JDK21 support
		newSteps.remove(0); // remove the filler step

		// if the last steps is a jump to the end, that is useless; remove it
		// TODO: replace with getLast() when we have full JDK21 support
		Step lastStep = newSteps.get(newSteps.size() -1);
		if (lastStep.getStepType() == Step.StepType.JMP && ((Jmp) lastStep).getDest() == -1) {
			// TODO: replace with removeLast() when we have full JDK21 support
			newSteps.remove(newSteps.size() -1);
		}

		// resolve the destinations for splits and jumps
		for (int i = 0; i < newSteps.size(); i++) {
			Step step = newSteps.get(i);
			switch (step.getStepType()) {
				case JMP:
					Jmp jmp = (Jmp) step;
					if (jmp.getDest() == -1) {
						// -1 signifies jump to the end
						jmp.setDest(newSteps.size());
					} else {
						// otherwise, we need to subtract 1 from each jump to take into account
						// filler step
						jmp.setDest(jmp.getDest() - 1);
					}
					break;
				case SPLITMULTI:
					List<Integer> dests = ((SplitMulti) step).getDests();
					if (dests.size() == 2) {
						// if there are 2 destinations, SplitMulti can become Split
						// again, subtract 1 to take into account filler step
						newSteps.set(i, new Split(dests.get(0) - 1, dests.get(1) - 1));
					}
					else {
						SplitMulti splitMultiNew = new SplitMulti();
						for (int dest : dests) {
							// -1 to take into account filler step
							splitMultiNew.addDest(dest - 1);
						}
						newSteps.set(i, splitMultiNew);
					}
					break;
				default:
					// do nothing
			}
		}
		return newSteps;
	}

	/**
	 * The actual method that deduplicates branches.
	 * @param branch current branch to process
	 * @param newSteps list of steps where deduplicated output is written to
	 * @param hashToIdx map to keep track of the branches that we have already seen
	 */
	private void deduplicateTree(InstructionNode branch, ArrayList<Step> newSteps, HashMap<InstructionNode, Integer> hashToIdx) {
		if (hashToIdx.keySet().contains(branch)) {
			// we have already seen this branch, which means this branch is a duplicate; we
			// will point the next step to be the branch that we've already seen
			branch.newStepsIdx = hashToIdx.get(branch);
			branch.doJump = true;
			return;
		}

		// we have never seen this branch before; add to list of steps
		hashToIdx.put(branch, newSteps.size());
		branch.newStepsIdx = newSteps.size();
		newSteps.add(branch.step);

		switch (branch.children.size()) {
			case 0:
				// if there are no children, we are at the end of a branch, so jump to the end
				newSteps.add(new Jmp(-1));
				break;
			case 1:
				// there only one next step, so no need to have a split
				// TODO: Change each of these three get(0) calls to getFirst() when full JDK 21 support is available
				deduplicateTree(branch.children.get(0), newSteps, hashToIdx);
				if (branch.children.get(0).doJump) {
					// if child branch is duplicated, just jump to the branch already seen
					newSteps.add(new Jmp(hashToIdx.get(branch.children.get(0))));
				}
				break;
			default:
				// 2 or more children, so split is required
				SplitMulti splitMulti = new SplitMulti();
				newSteps.add(splitMulti);
				for (InstructionNode child : branch.children) {
					deduplicateTree(child, newSteps, hashToIdx);
					// add the appropriate location to jump to
					splitMulti.addDest(child.newStepsIdx);
				}
		}
	}
}