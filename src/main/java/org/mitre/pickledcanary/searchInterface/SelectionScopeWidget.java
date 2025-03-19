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


import java.awt.Component;
import java.awt.event.ActionEvent;
import java.util.*;

import javax.swing.*;

import docking.widgets.button.GRadioButton;
import ghidra.app.plugin.core.instructionsearch.ui.ControlPanelWidget;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;

/**
 * Allows the user to define a custom search range for Pickled Canary.
 * 
 * This is a copy of Ghidra's existing SelectionScopeWidget but without the need for a dialog.
 * 
 * TODO: We should change to using Ghidra's version of this class if we change the PC GUI to a
 * dialog.
 *
 */
public class SelectionScopeWidget extends ControlPanelWidget {

	// Toggle button that when active, allows the user to set a new search range.
	private JRadioButton searchAllRB;
	private JRadioButton searchSelectionRB;

	// Stores the current search range settings.
	private List<AddressRange> searchRanges = new ArrayList<>();
 
	private PickledCanarySearchTablePlugin plugin;

	/**
	 * 
	 * @param plugin
	 * @param title
	 * @param dialog
	 */
	public SelectionScopeWidget(PickledCanarySearchTablePlugin plugin, String title) {
		super(title);

		this.plugin = plugin; 
	}

	/**
	 * Returns the current search range.
	 */
	public List<AddressRange> getSearchRange() {
		if (searchAllRB.isSelected()) {
			updateSearchRangeAll();
		}
		else {
			updateSearchRangeBySelection();

		}

		return searchRanges;
	}

	/**
	 * Updates the current search range to encompass the entire program.
	 */
	public void updateSearchRangeAll() {

		if (plugin == null) {
			return;
		}

		searchRanges.clear();
		AddressRangeIterator iterator =
			plugin.getCurrentProgram()
					.getMemory()
					.getLoadedAndInitializedAddressSet()
					.getAddressRanges();
		while (iterator.hasNext()) {
			searchRanges.add(iterator.next());
		}

	}

	/**
	 * Retrieves the currently-selected region in the listing and makes that the new search
	 * range.
	 */
	public void updateSearchRangeBySelection() {

		// if the user has set the toggle to "Selection", then update the search range,
		// otherwise leave alone.
		if (!searchSelectionRB.isSelected()) {
			return;
		}

		// If were here, then the user has selected the "Selection" radio button, so
		// we're about to update our range based on what is currently selected; start by clearing
		// out our current range.
		searchRanges.clear();

		if (plugin.getProgramSelection() == null) {
			return;
		}
		if (plugin.getProgramSelection().getMinAddress() == null ||
			plugin.getProgramSelection().getMaxAddress() == null) {
			return;
		}

		Iterator<AddressRange> iter = plugin.getProgramSelection().getAddressRanges();
		while (iter.hasNext()) {
			searchRanges.add(iter.next());
		}
	}

	/*********************************************************************************************
	 * PROTECTED METHODS
	 ********************************************************************************************/

	@Override
	protected JPanel createContent() {

		JPanel contentPanel = new JPanel();
		contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.X_AXIS));
		contentPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

		searchAllRB = createSearchRB(new SearchAllAction(), "Entire Program",
			"When active, the entire program will be used for the search.");
		searchAllRB.setSelected(true);
		contentPanel.add(searchAllRB);

		searchSelectionRB = createSearchRB(new SearchSelectionAction(), "Selection",
			"When active, code selections on the listing will change the search range.");
		contentPanel.add(searchSelectionRB);

		ButtonGroup group = new ButtonGroup();
		group.add(searchAllRB);
		group.add(searchSelectionRB);

		return contentPanel;
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	/**
	 * Invoked when the user clicks the radio button that allows them to select a 
	 * custom search range.
	 */
	private class SearchSelectionAction extends AbstractAction {
		@Override
		public void actionPerformed(ActionEvent arg0) {
			updateSearchRangeBySelection(); 
		}
	}

	/**
	 * Invoked when the user selects the button to set the search range to cover the
	 * entire program.
	 */
	private class SearchAllAction extends AbstractAction {
		@Override
		public void actionPerformed(ActionEvent arg0) {
			updateSearchRangeAll(); 
		}
	}

	private JRadioButton createSearchRB(AbstractAction action, String name, String tooltip) {
		GRadioButton button = new GRadioButton(action);
		button.setName(name);
		button.setText(name);
		button.setToolTipText(tooltip);
		button.setAlignmentX(Component.LEFT_ALIGNMENT);
		return button;
	}
}
