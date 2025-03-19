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

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.searchInterface;

import java.math.BigInteger;

import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

/**
 * Represents a row in the {@link ContextHelper} table.
 */
public record ContextTableEntry(Register reg, RegisterValue value) {

	public String getValueString() {
		if (value == null || value.getValueMask().equals(BigInteger.ZERO)) {
			return "[Instruction context has not been set]";
		}
		Register baseReg = value.getRegister();
		if (!baseReg.hasChildren()) {
			return "0x" + value.getUnsignedValueIgnoreMask().toString(16);
		}
		StringBuilder buf = new StringBuilder();

		int paddedLen = 0;
		for (Register childReg : baseReg.getChildRegisters()) {
			int len = childReg.getName().length();
			if (len > paddedLen) {
				paddedLen = len;
			}
		}

		RegisterValue childActualValue = value.getRegisterValue(reg);
		if (childActualValue.hasAnyValue()) {
			BigInteger actual = childActualValue.getUnsignedValueIgnoreMask();
			buf.append("0x" + actual.toString(16));
		}
		else {
			buf.append("--");
		}
		return buf.toString();
	}

	int getMsb() {
		return this.getBaseRegSize() - reg.getLeastSignificantBitInBaseRegister() - 1;
	}

	int getLsb() {
		return this.getMsb() - reg.getBitLength() + 1;
	}

	RegisterValue getChildActualValue() {
		return value.getRegisterValue(reg);
	}

	private int getBaseRegSize() {
		Register baseReg = value.getRegister();
		return baseReg.getMinimumByteSize() * 8;
	}

}
