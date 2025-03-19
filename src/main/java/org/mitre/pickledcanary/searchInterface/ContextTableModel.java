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

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import javax.swing.event.TableModelEvent;

import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModelStub;

/**
 * Model for the table of context variables used in {@link ContextHelper}
 */
class ContextTableModel extends ThreadedTableModelStub<ContextTableEntry> {

	private final String SELECTED_COLUMN_NAME = "Set";
	private PickledCanarySearchTablePlugin plugin;
	private ContextHelper contextHelper;

	ContextTableModel(PickledCanarySearchTablePlugin plugin, ContextHelper contextHelper) {
		super("Context Table Model", plugin.getTool());
		this.plugin = plugin;
		this.contextHelper = contextHelper;
	}

	@Override
	public boolean isCellEditable(int row, int col) {

		DynamicTableColumn<ContextTableEntry, ?, ?> column = getColumn(col);
		String columnName = column.getColumnName();
		if (SELECTED_COLUMN_NAME.equals(columnName)) {
			return true;
		}
		return false;
	}

	@Override
	public void setValueAt(Object value, int row, int col) {
		DynamicTableColumn<ContextTableEntry, ?, ?> column = getColumn(col);
		String columnName = column.getColumnName();
		if (SELECTED_COLUMN_NAME.equals(columnName)) {
			if ((Boolean) value) {
				contextHelper.addRegister(this.getAllData().get(row).getChildActualValue());
			}
			else {
				contextHelper.removeRegister(this.getAllData().get(row).getChildActualValue());
			}
		}
		fireTableCellUpdated(row, col);
	}

	@Override
	protected TableColumnDescriptor<ContextTableEntry> createTableColumnDescriptor() {
		TableColumnDescriptor<ContextTableEntry> descriptor =
			new TableColumnDescriptor<ContextTableEntry>();

		descriptor.addVisibleColumn(new ContxtVarSelectedTableColumn());
		descriptor.addVisibleColumn(new ContxtVarNameTableColumn(), 1, true);
		descriptor.addVisibleColumn(new ContxtVarValueTableColumn());
		descriptor.addVisibleColumn(new ContxtVarLsbTableColumn());
		descriptor.addVisibleColumn(new ContxtVarMsbTableColumn());

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<ContextTableEntry> accumulator, TaskMonitor monitor)
			throws CancelledException {

		Program currentProgram = plugin.getCurrentProgram();

		Register contextReg = currentProgram.getProgramContext().getBaseContextRegister();
		
		Instruction instruction = currentProgram.getListing()
				.getInstructionAt(plugin.getCurrentAddress());
		if (instruction == null) {
			return;
		}
		RegisterValue rv = instruction
				.getRegisterValue(contextReg);
		if (rv == null) {
			return;
		}

		for (Register reg : rv.getRegister().getChildRegisters()) {
			accumulator.add(new ContextTableEntry(reg, rv));
		}
	}

	public void fireTableChanged(TableModelEvent e) {
		Swing.runIfSwingOrRunLater(() -> super.fireTableChanged(e));
	}

// ==================================================================================================
// Inner Classes
// ==================================================================================================
	private class ContxtVarSelectedTableColumn
			extends AbstractDynamicTableColumn<ContextTableEntry, Boolean, Object> {

		@Override
		public String getColumnDescription() {
			return "When selected, the script has been added as an action to the tool";
		}

		@Override
		public String getColumnName() {
			return SELECTED_COLUMN_NAME;
		}

		@Override
		public Boolean getValue(ContextTableEntry rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return contextHelper.containsRegister(rowObject.getChildActualValue());
		}

		@Override
		public int getColumnPreferredWidth() {
			return 10;
		}
	}

	private class ContxtVarNameTableColumn extends
			AbstractDynamicTableColumn<ContextTableEntry, String, Object> {

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public String getValue(ContextTableEntry rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.reg().getName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private class ContxtVarValueTableColumn extends
			AbstractDynamicTableColumn<ContextTableEntry, String, Object> {

		@Override
		public String getColumnName() {
			return "Value";
		}

		@Override
		public String getValue(ContextTableEntry rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getValueString();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 50;
		}
	}

	private class ContxtVarLsbTableColumn extends
			AbstractDynamicTableColumn<ContextTableEntry, Integer, Object> {

		@Override
		public String getColumnName() {
			return "LSB";
		}

		@Override
		public String getColumnDescription() {
			return "The least signficant bit this variable occupies in the overall context register";
		}

		@Override
		public Integer getValue(ContextTableEntry rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getLsb();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 10;
		}
	}

	private class ContxtVarMsbTableColumn extends
			AbstractDynamicTableColumn<ContextTableEntry, Integer, Object> {

		@Override
		public String getColumnName() {
			return "MSB";
		}

		@Override
		public String getColumnDescription() {
			return "The most signficant bit this variable occupies in the overall context register";
		}

		@Override
		public Integer getValue(ContextTableEntry rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getMsb();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 10;
		}
	}
}
