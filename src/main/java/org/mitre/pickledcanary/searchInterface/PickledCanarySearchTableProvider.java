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
 * Based on Ghidra's sample SampleSearchTableProvider.
 */

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.searchInterface;

import docking.ActionContext;
import docking.DockingUtils;
import docking.UndoRedoKeeper;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;
import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.search.SavedDataAddresses;
import resources.Icons;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;

public class PickledCanarySearchTableProvider extends ComponentProviderAdapter
		implements OptionsChangeListener {

	private static final String COMMIT_ACTION = "commit";
	private final PickledCanarySearchTablePlugin plugin;
	private final JComponent component;
	protected JTextArea textArea;
	protected JTextArea textAreaCompiled;
	protected JCheckBox removeDebugCheckbox;
	private GhidraThreadedTablePanel<SavedDataAddresses> filterTable;
	private PickledCanarySearchTableModel model;
	private DockingAction saveAction;
	private DockingAction saveCompiledAsAction;
	private DockingAction saveCompiledAction;
	private File selectedFile;
	private File selectedCompiledFile;
	private PickledCanarySearcher searcher;
	private SelectionScopeWidget scope;
	private ContextHelper contextHelper;
	private UndoRedoKeeper undoRedoKeeper;

	public PickledCanarySearchTableProvider(PickledCanarySearchTablePlugin plugin,
			String initialValue) {
		super(plugin.getTool(), "Pickled Canary Search", plugin.getName());
		this.plugin = plugin;
		component = build(initialValue);
		createActions();
	}

	private void doSearch(boolean removeDebugFlag) {
		searcher.setQuery(textArea.getText(), removeDebugFlag);
		searcher.setRange(scope.getSearchRange());
		saveCompiledAsAction.setEnabled(false);
		saveCompiledAction.setEnabled(false);
		model.doClearData();
		model.reload();
	}

	String getPatternText() {
		return textArea.getText();
	}

	void setPatternText(String pattern) {
		textArea.setText(pattern);
		PickledCanarySearchTableProvider.this.saveAction
				.setEnabled(PickledCanarySearchTableProvider.this.selectedFile != null);
	}

	void insertIntoPatternTextAtCursor(String toInsert) {
		textArea.insert(toInsert, textArea.getCaretPosition());
		PickledCanarySearchTableProvider.this.saveAction
		.setEnabled(PickledCanarySearchTableProvider.this.selectedFile != null);
	}

	private JComponent build(String initialValue) {
		JPanel container = new JPanel(new BorderLayout());

		JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		JPanel compiledTab = new JPanel(new BorderLayout());
		removeDebugCheckbox = new JCheckBox("Remove Debug Information", false);

		JPanel searchPanel = new JPanel(new BorderLayout());

		JPanel patternPanel = new JPanel(new BorderLayout());
		patternPanel.setBorder(
			new CompoundBorder(new TitledBorder("Pattern"), new EmptyBorder(5, 5, 5, 5)));

		textArea = new JTextArea(5, 25);
		textArea.setEditable(true);
		textArea.setMargin(new Insets(5, 5, 5, 5));
		textArea.setText(initialValue);
		undoRedoKeeper = DockingUtils.installUndoRedo(textArea);

		InputMap im = textArea.getInputMap();
		ActionMap am = textArea.getActionMap();
		im.put(KeyStroke.getKeyStroke("control ENTER"), COMMIT_ACTION);
		am.put(COMMIT_ACTION, new CommitAction());

		textArea.addKeyListener(new KeyListener() {

			@Override
			public void keyTyped(KeyEvent e) {
				// Not handled
			}

			@Override
			public void keyPressed(KeyEvent e) {
				// Not handled
			}

			@Override
			public void keyReleased(KeyEvent e) {
				PickledCanarySearchTableProvider.this.saveAction
						.setEnabled(PickledCanarySearchTableProvider.this.selectedFile != null);
			}
		});

		patternPanel.add(new JScrollPane(textArea), BorderLayout.CENTER);

		JTabbedPane tabbedPanel = new JTabbedPane();

		contextHelper = new ContextHelper(plugin, this);
		Component contextPanel = contextHelper.buildContextPanel();

		tabbedPanel.addTab("Context", Icons.get("images/flag_green.png"), contextPanel,
			"See Context information");
		tabbedPanel.setMnemonicAt(0, KeyEvent.VK_1);

		JPanel resultsPanel = new JPanel(new BorderLayout());

		ProgramLocation pl = plugin.getProgramLocation();
		Address currentAddress;
		if (pl == null) {
			currentAddress = plugin.getCurrentProgram().getMinAddress();
		}
		else {
			currentAddress = pl.getAddress();
		}

		searcher = new PickledCanarySearcher(plugin.getCurrentProgram(), currentAddress,
			textArea.getText());
		model = new PickledCanarySearchTableModel(searcher, plugin.getTool()); // Results tab

		// Watch for changes in the table and pull/re-pull the compiled pattern into the
		// results text box when we have results.
		model.addTableModelListener(e -> {
			String s = searcher.getCompiledPattern();
			if (s.compareTo(
				PickledCanarySearchTableProvider.this.textAreaCompiled.getText()) != 0) {
				PickledCanarySearchTableProvider.this.textAreaCompiled.setText(s);
				if (!s.equals(PickledCanarySearcher.COMPILING_PATTERN) &&
					!s.equals(PickledCanarySearcher.NOT_COMPILED_STRING)) {
					saveCompiledAction
							.setEnabled(
								PickledCanarySearchTableProvider.this.selectedCompiledFile != null);
					saveCompiledAsAction.setEnabled(true);
				}
			}
			int unfilteredRowCount = model.getUnfilteredRowCount();
			int rowCount = model.getRowCount();

			String titleCount = rowCount + " items";
			if (unfilteredRowCount != rowCount) {
				titleCount += " (of " + unfilteredRowCount + ")";
			}
			PickledCanarySearchTableProvider.this.setTitle(
				"Pickled Canary Search Results - " + titleCount);
		});

		searcher.addListener(e -> {
			String s = searcher.getCompiledPattern();
			PickledCanarySearchTableProvider.this.textAreaCompiled.setText(s);
			saveCompiledAction.setEnabled(
				PickledCanarySearchTableProvider.this.selectedCompiledFile != null);
			saveCompiledAsAction.setEnabled(true);
		});

		// listener for Remove Debug Info Checkbox
		removeDebugCheckbox.addItemListener(e ->
		// refreshing and recompiling the pattern WITHOUT the debug information
		// refreshing and recompiling the pattern WITH the debug information
		doSearch(e.getStateChange() == ItemEvent.SELECTED));

		filterTable = new GhidraThreadedTablePanel<>(model, 500, 1000);
		GhidraTable table = filterTable.getTable();

		table.installNavigation(tool);
		table.setNavigateOnSelectionEnabled(true);
		resultsPanel.add(filterTable);

		tabbedPanel.addTab("Results", Icons.SORT_DESCENDING_ICON, resultsPanel, "Show Results");
		tabbedPanel.setMnemonicAt(1, KeyEvent.VK_2);

		textAreaCompiled = new JTextArea(5, 25);
		textAreaCompiled.setEditable(false);
		textAreaCompiled.setMargin(new Insets(5, 5, 5, 5));
		textAreaCompiled.setText("Compile the pattern first...");

		compiledTab.add(new JScrollPane(textAreaCompiled), BorderLayout.CENTER);
		compiledTab.add(removeDebugCheckbox, BorderLayout.PAGE_END);

		tabbedPanel.addTab("Compiled", Icons.get("images/checkmark_yellow.gif"), compiledTab,
			"Show compiled pattern");
		tabbedPanel.setMnemonicAt(2, KeyEvent.VK_3);

		JPanel control = new JPanel(new BorderLayout());
		scope = new SelectionScopeWidget(this.plugin, "Search Scope");
		control.add(scope, BorderLayout.NORTH);
		JButton searchButton = new JButton("Search");
		searchButton.addActionListener(l -> doSearch(removeDebugCheckbox.isSelected()));
		searchButton.setToolTipText("Ctrl-Enter in the pattern box to search");
		control.add(searchButton);

		searchPanel.add(patternPanel, BorderLayout.CENTER);
		searchPanel.add(control, BorderLayout.SOUTH);

		tabbedPanel.setSelectedIndex(1);

		splitPane.setLeftComponent(searchPanel);
		splitPane.setRightComponent(tabbedPanel);

		container.add(splitPane, BorderLayout.CENTER);

		setVisible(true);
		return container;
	}

	private void createActions() {
		// ## Open pattern
		DockingAction openAction = new DockingAction("Load pattern", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {

				try {
					PickledCanarySearchTableProvider.this.selectedFile =
						PickledCanary.pcAskFile(false,
							PickledCanary.AskFileType.Pattern,
							PickledCanarySearchTableProvider.this.selectedFile);
				}
				catch (CancelledException e) {
					return;
				}

				String query;
				try {
					query = Files.readString(
						PickledCanarySearchTableProvider.this.selectedFile.toPath());
				}
				catch (IOException e) {
					e.printStackTrace();
					return;
				}
				saveAction.setEnabled(false);
				textArea.setText(query);
				removeDebugCheckbox.setSelected(false);
				doSearch(false);
			}
		};
		openAction.setToolBarData(new ToolBarData(Icons.OPEN_FOLDER_ICON, null));
		openAction.setEnabled(true);
		openAction.markHelpUnnecessary();
		dockingTool.addLocalAction(this, openAction);

		// ## Save pattern as
		DockingAction saveAsAction = new DockingAction("Save pattern as", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {

				try {
					PickledCanarySearchTableProvider.this.selectedFile =
						PickledCanary.pcAskFile(true,
							PickledCanary.AskFileType.Pattern,
							PickledCanarySearchTableProvider.this.selectedFile);
				}
				catch (CancelledException e) {
					return;
				}

				if (selectedFile.exists()) {
					final boolean overwrite = OptionDialog.showYesNoDialog(null, "Confirm Save As",
						selectedFile.getName() +
							" already exists.\nDo you want to replace it?") == OptionDialog.OPTION_ONE;
					if (!overwrite) {
						return;
					}
				}

				PickledCanarySearchTableProvider.this.saveAction.setEnabled(false);

				try (FileWriter fileWriter = new FileWriter(selectedFile)) {
					fileWriter.write(textArea.getText());
				}
				catch (IOException e) {
					Msg.showError(this, null, "Error writing file",
						"Got an error writing the specified file. See details for more information",
						e);
				}

			}
		};
		saveAsAction.setToolBarData(new ToolBarData(Icons.SAVE_AS_ICON, null));
		saveAsAction.setEnabled(true);
		saveAsAction.markHelpUnnecessary();
		dockingTool.addLocalAction(this, saveAsAction);

		// ## Save Pattern
		saveAction = new DockingAction("Save pattern", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				try (FileWriter fileWriter = new FileWriter(selectedFile)) {
					fileWriter.write(textArea.getText());
				}
				catch (IOException e) {
					Msg.showError(this, null, "Error writing file",
						"Got an error writing the specified file. See details for more information",
						e);
				}
				this.setEnabled(false);

			}
		};
		saveAction.setToolBarData(new ToolBarData(Icons.get("images/disk.png"), null));
		saveAction.setEnabled(this.selectedFile != null);
		saveAction.markHelpUnnecessary();
		dockingTool.addLocalAction(this, saveAction);

		final ImageIcon compiledPatternIcon =
			ResourceManager.getImageIcon(new MultiIcon(Icons.get("images/disk.png"),
				new TranslateIcon(ResourceManager.loadImage("images/cache.png", 10, 10), 6,
					6)));

		// ## Save compiled pattern as
		saveCompiledAsAction = new DockingAction("Save compiled pattern as", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {

				File baseFile = PickledCanarySearchTableProvider.this.selectedCompiledFile;
				if (baseFile == null) {
					baseFile = PickledCanarySearchTableProvider.this.selectedFile;
				}
				try {
					PickledCanarySearchTableProvider.this.selectedCompiledFile =
						PickledCanary.pcAskFile(true,
							PickledCanary.AskFileType.JSON, baseFile);
				}
				catch (CancelledException e) {
					return;
				}

				if (selectedCompiledFile.exists()) {
					final boolean overwrite = OptionDialog.showYesNoDialog(null, "Confirm Save As",
						selectedCompiledFile.getName() +
							" already exists.\nDo you want to replace it?") == OptionDialog.OPTION_ONE;
					if (!overwrite) {
						return;
					}
				}

				PickledCanarySearchTableProvider.this.saveCompiledAsAction.setEnabled(false);
				PickledCanarySearchTableProvider.this.saveCompiledAction.setEnabled(false);

				try (FileWriter fileWriter = new FileWriter(selectedCompiledFile)) {
					fileWriter.write(textAreaCompiled.getText());
				}
				catch (IOException e) {
					Msg.showError(this, null, "Error writing file",
						"Got an error writing the specified file. See details for more information",
						e);
				}

			}
		};

		saveCompiledAsAction.setToolBarData(
			new ToolBarData(new DotDotDotIcon(compiledPatternIcon), null));
		saveCompiledAsAction.setEnabled(false);
		saveCompiledAsAction.markHelpUnnecessary();
		dockingTool.addLocalAction(this, saveCompiledAsAction);

		// ## Save compiled pattern
		saveCompiledAction = new DockingAction("Save compiled pattern", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				try (FileWriter fileWriter = new FileWriter(selectedCompiledFile)) {
					fileWriter.write(textAreaCompiled.getText());
				}
				catch (IOException e) {
					Msg.showError(this, null, "Error writing file",
						"Got an error writing the specified file. See details for more information",
						e);
				}
				this.setEnabled(false);

			}
		};
		saveCompiledAction.setToolBarData(new ToolBarData(compiledPatternIcon, null));
		saveCompiledAction.setEnabled(this.selectedCompiledFile != null);
		saveCompiledAction.markHelpUnnecessary();
		dockingTool.addLocalAction(this, saveCompiledAction);

		// ## Refresh / Run pattern
		DockingAction action = new DockingAction("Run pattern and reload results", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				doSearch(removeDebugCheckbox.isSelected());
			}
		};
		action.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);

	}

	public void dispose() {
		filterTable.dispose();
		filterTable.getTable().dispose();
		contextHelper.dispose();
		undoRedoKeeper.clear();
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		// Do nothing
	}

	public void updateContextInfo() {
		contextHelper.updateContextInfo();
	}

	// Creates a 16x16 icon with a scaled base icon and puts 3 dots below it.
	// THIS IS A COPY OF THE PRIVATE CLASS IN Icons
	private record DotDotDotIcon(Icon base) implements Icon {
		private DotDotDotIcon(Icon base) {
			this.base = ResourceManager.getScaledIcon(base, 12, 12);
		}

		@Override
		public void paintIcon(Component c, Graphics g, int x, int y) {
			base.paintIcon(c, g, x, y);
			g.setColor(new Color(50, 50, 50));
			g.fillRect(x + 6, y + 14, 2, 2);
			g.fillRect(x + 9, y + 14, 2, 2);
			g.fillRect(x + 12, y + 14, 2, 2);

		}

		@Override
		public int getIconWidth() {
			return 16;
		}

		@Override
		public int getIconHeight() {
			return 16;
		}
	}

	private class CommitAction extends AbstractAction {
		public void actionPerformed(ActionEvent ev) {
			doSearch(removeDebugCheckbox.isSelected());
		}
	}

}