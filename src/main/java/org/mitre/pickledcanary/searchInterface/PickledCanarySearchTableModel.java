package org.mitre.pickledcanary.searchInterface;

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

/*
 * Based on Ghidra's sample SampleSearchTableModel. 
 */

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.task.TaskMonitor;
import java.util.Arrays;

import org.mitre.pickledcanary.search.SavedDataAddresses;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;

/** contains the GUI design for the Results tab */
public class PickledCanarySearchTableModel extends AddressBasedTableModel<SavedDataAddresses> {

	private final PickledCanarySearcher searcher;  // todo: make this serializable

	public PickledCanarySearchTableModel(PickledCanarySearcher searcher, PluginTool tool) {
		super("Pickled Canary Search Results", tool, searcher.getProgram(), null, true);
		this.searcher = searcher;
	}

	@Override
	protected void doLoad(Accumulator<SavedDataAddresses> accumulator, TaskMonitor monitor) throws CancelledException {
		try {
			searcher.search(accumulator, monitor);
		} catch (RuntimeException e) {
			Msg.showError(this, null, "Pattern Search Error",
					"Encountered an error while trying to search for the given pattern. See details for more information.",
					e);
			searcher.setCompiledPattern(
					"Pattern compile failed!\n" + e.getMessage() + "\n\n" +
							Arrays.toString(e.getStackTrace()));
		}
	}

	/**
	 * Clears all the data from this table (so we don't show stale results)
	 */
	public void doClearData() {
		this.clearData();
	}

	@Override
	protected TableColumnDescriptor<SavedDataAddresses> createTableColumnDescriptor() {
		TableColumnDescriptor<SavedDataAddresses> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new MyAddressColumn());
		descriptor.addVisibleColumn(new MyAddressEndColumn());
		descriptor.addVisibleColumn(new MyValueColumn());
		descriptor.addVisibleColumn(new MyLengthColumn());

		return descriptor;
	}

	private static class MyAddressColumn extends AbstractDynamicTableColumn<SavedDataAddresses, Address, Object> {

		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public Address getValue(SavedDataAddresses rowObject, Settings settings, Object data, ServiceProvider services)
				throws IllegalArgumentException {
			return rowObject.getStart();
		}
	}

	private static class MyAddressEndColumn extends AbstractDynamicTableColumn<SavedDataAddresses, Address, Object> {

		@Override
		public String getColumnName() {
			return "End Address";
		}

		@Override
		public Address getValue(SavedDataAddresses rowObject, Settings settings, Object data, ServiceProvider services)
				throws IllegalArgumentException {
			return rowObject.getEnd();
		}
	}

	private static class MyValueColumn extends AbstractDynamicTableColumn<SavedDataAddresses, String, Object> {

		@Override
		public String getColumnName() {
			return "Values";
		}

		@Override
		public String getValue(SavedDataAddresses rowObject, Settings settings, Object data, ServiceProvider services)
				throws IllegalArgumentException {
			String out = rowObject.getVarsString();
			String labels = rowObject.getLabelsString();
			if (labels != null && labels.length() > 0) {
				if (out != null && out.length() > 0) {
					out += ", ";
				}
				out += labels;
			}
			return out;
		}
	}

	private static class MyLengthColumn extends AbstractDynamicTableColumn<SavedDataAddresses, Long, Object> {

		@Override
		public String getColumnName() {
			return "Match Length";
		}

		@Override
		public Long getValue(SavedDataAddresses rowObject, Settings settings, Object data, ServiceProvider services)
				throws IllegalArgumentException {
			return rowObject.getEnd().getOffsetAsBigInteger().subtract(rowObject.getStart().getOffsetAsBigInteger())
					.longValue();
		}
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).getStart();
	}
}