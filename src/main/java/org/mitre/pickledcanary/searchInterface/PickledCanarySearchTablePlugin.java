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
 * Based on Ghidra's sample SampleSearchTablePlugin. 
 */

// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.app.CorePluginPackage;

//@formatter:off
@PluginInfo(
		status = PluginStatus.RELEASED, 
		packageName = CorePluginPackage.NAME, 
		category = PluginCategoryNames.SEARCH, 
		shortDescription = "Pickled Canary Search Table Plugin", 
		description = "Plugin for searching using Pickled Canary patterns and creating a table for the results"
)
//@formatter:on
/**
 * This plugin provides a menu entry under "Search" to launch the Pickled Canary
 * search window
 */
public class PickledCanarySearchTablePlugin extends ProgramPlugin {

	private PickledCanarySearchTableProvider provider;

	private enum LastActionType {
		ADDRESS, SELECTION
	}

	private Address currentAddressLocal;
	private ProgramSelection currentSelectionLocal;
	private LastActionType lastAction;

	public PickledCanarySearchTablePlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	@Override
	protected void dispose() {
		if (provider != null) {
			provider.dispose();
		}
	}

	private void createActions() {
		DockingAction action = new DockingAction("Search Stuff", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {

				search();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null;
			}
		};
		action.setMenuBarData(new MenuData(new String[] { "Search", "Pickled Canary Pattern" }, "MyGroup"));
		tool.addAction(action);
	}

	protected void search() {
		StringBuilder initialValue = new StringBuilder();

		Listing listing = currentProgram.getListing();
		if (listing != null) {
			if (this.lastAction == LastActionType.ADDRESS && currentAddressLocal != null) {
				Instruction instruction = listing.getInstructionAt(currentAddressLocal);
				if (instruction != null) {
					initialValue = new StringBuilder(instruction.toString());
				}
			} else if (this.lastAction == LastActionType.SELECTION && currentSelectionLocal != null) {
				for (Instruction i : listing.getInstructions(this.currentSelectionLocal, true)) {
					initialValue.append(i.toString()).append("\n");
				}
			}

		}
		provider = new PickledCanarySearchTableProvider(this, initialValue.toString());
//		tool.addComponentProvider(provider, true);
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		if (loc != null) {
			this.currentAddressLocal = loc.getAddress();
			this.lastAction = LastActionType.ADDRESS;
		}
	}

	@Override
	protected void selectionChanged(ProgramSelection selection) {
		if (selection != null) {
			this.currentSelectionLocal = selection;
			this.lastAction = LastActionType.SELECTION;
		}
	}
}