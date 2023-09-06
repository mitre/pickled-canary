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

import java.util.List;

/**
 * A {@link AssemblyResolution} indicating the occurrence of a (usually semantic) error
 * 
 * <p>
 * The description should indicate where the error occurred. The error message should explain the
 * actual error. To help the user diagnose the nature of the error, errors in sub-constructors
 * should be placed as children of an error given by the parent constructor.
 */
public class AssemblyResolvedError extends AssemblyResolution {
	protected final String error;

	@Override
	protected int computeHash() {
		return error.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AssemblyResolvedError)) {
			return false;
		}
		AssemblyResolvedError that = (AssemblyResolvedError) obj;
		if (!this.error.equals(that.error)) {
			return false;
		}
		return true;
	}

	/**
	 * @see AssemblyResolution#error(String, String, List)
	 */
	AssemblyResolvedError(String description, List<? extends AssemblyResolution> children,
			AssemblyResolution right, String error) {
		super(description, children, right);
		AssemblyTreeResolver.DBG.println(error);
		this.error = error;
	}

	@Override
	public boolean isError() {
		return true;
	}

	@Override
	public boolean isBackfill() {
		return false;
	}

	/**
	 * Get a description of the error
	 * 
	 * @return the description
	 */
	public String getError() {
		return error;
	}

	@Override
	public String lineToString() {
		return error + " (" + description + ")";
	}

	@Override
	public AssemblyResolution shift(int amt) {
		return this;
	}

	@Override
	public AssemblyResolution withRight(AssemblyResolution right) {
		return new AssemblyResolvedError(description, null, right, error);
	}

	@Override
	public AssemblyResolution parent(String description, int opCount) {
		List<AssemblyResolution> allRight = getAllRight();
		return new AssemblyResolvedError(description, allRight, null, error);
	}
}
