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

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.util.Collection;
import java.util.HashSet;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;

import docking.widgets.table.GFilterTable;
import docking.widgets.button.GRadioButton;
import ghidra.app.plugin.core.instructionsearch.ui.ControlPanelWidget;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

/**
 * Helper panel which computes computes and displays different context variable steps for Pickled
 * Canary
 */
public class ContextHelper {

	private static final String CONTEXT_HINT =
		"Context variables at the currently selected address";
	private static final String INSERT_AT_START_BUTTON_TEXT = "Insert at Start";
	private static final String REPLACE_AT_START_BUTTON_TEXT = "Replace at Start";
	private static final String INSERT_BUTTON_TEXT = "Insert at Cursor";

	enum Mode {
		SELECTION,
		AT_ADDRESS,
		AT_ADDRESS_COMPACT,
	}

	PickledCanarySearchTablePlugin plugin;
	PickledCanarySearchTableProvider provider;

	JSplitPane contextPanel;
	private ContextTableModel contextTableModel;
	private GFilterTable<ContextTableEntry> contextFilterTable;
	TitledBorder contextPanelLabel;
	JTextArea previewLabel;
	Collection<RegisterValue> previewContext = new HashSet<>();
	Mode mode = Mode.SELECTION;
	JButton insertAtStartButton;

	private final String contextStartRegexString = "^`CONTEXT[^`]+`";
	private final Pattern contextStartPattern =
		Pattern.compile(contextStartRegexString, Pattern.DOTALL);

	public ContextHelper(PickledCanarySearchTablePlugin plugin,
			PickledCanarySearchTableProvider provider) {
		this.plugin = plugin;
		this.provider = provider;
		provider.textArea.getDocument().addDocumentListener(new DocumentListener() {

			@Override
			public void insertUpdate(DocumentEvent e) {
				patternChangedHandler();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				patternChangedHandler();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				patternChangedHandler();
			}
		});
	}

	private void patternChangedHandler() {
		String pattern = provider.getPatternText();
		if (contextStartPattern.matcher(pattern).find()) {
			insertAtStartButton.setText(REPLACE_AT_START_BUTTON_TEXT);
		}
		else {
			insertAtStartButton.setText(INSERT_AT_START_BUTTON_TEXT);
		}
	}

	/**
	 * Create the main panel showing context information
	 */
	Component buildContextPanel() {
		contextPanel = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		contextPanel.setResizeWeight(.7d);
		JPanel contextTablePanel = new JPanel(new BorderLayout());
		contextTablePanel.add(buildContextTablePanel(), BorderLayout.CENTER);
		contextPanelLabel = new TitledBorder(getContextPanelHint());
		contextTablePanel
				.setBorder(new CompoundBorder(contextPanelLabel, new EmptyBorder(5, 5, 5, 5)));

		contextPanel.setLeftComponent(contextTablePanel);
		contextPanel.setRightComponent(buildContextPreviewPanel());
		return contextPanel;
	}

	private Component buildContextTablePanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));

		contextTableModel = new ContextTableModel(plugin, this);
		contextFilterTable = new GFilterTable<ContextTableEntry>(contextTableModel);
		panel.add(contextFilterTable);

		contextTableModel.addTableModelListener(new TableModelListener() {
			@Override
			public void tableChanged(TableModelEvent e) {
				updatePreview();
			}
		});
		return panel;
	}

	private void insertAtStart() {
		String before = provider.getPatternText();
		String replacement;
		if (contextStartPattern.matcher(before).find()) {
			replacement = before.replaceAll("(?s)" + contextStartRegexString, getPreviewText());
		}
		else {
			replacement = getPreviewText() + "\n" + before;
		}
		provider.setPatternText(replacement);
	}

	private void insertAtCursor() {
		provider.insertIntoPatternTextAtCursor("\n" + getPreviewText() + "\n");
	}

	private Component buildContextPreviewPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		previewLabel = new JTextArea(getContextPanelHint(), 5, 20);
		previewLabel.setEditable(false);
		previewLabel.setMargin(new Insets(5, 5, 5, 5));
		JPanel container = new JPanel(new BorderLayout());
		container.setBorder(new CompoundBorder(new TitledBorder("Context Step Preview"),
			new EmptyBorder(5, 5, 5, 5)));
		container.add(new JScrollPane(previewLabel));
		panel.add(container, BorderLayout.CENTER);

		JPanel buttons = new JPanel(new FlowLayout());

		insertAtStartButton = new JButton(INSERT_AT_START_BUTTON_TEXT);
		insertAtStartButton.addActionListener(l -> insertAtStart());

		JButton insertButton = new JButton(INSERT_BUTTON_TEXT);
		insertButton.addActionListener(l -> insertAtCursor());

		buttons.add(insertAtStartButton);
		buttons.add(insertButton);

		panel.add(buttons, BorderLayout.SOUTH);

		JPanel modeSelector = new ContextPreviewTypeSelector(this);
		panel.add(modeSelector, BorderLayout.NORTH);
		return panel;
	}

	private String getContextPanelHint() {
		return CONTEXT_HINT + " (0x" + plugin.getCurrentAddress().toString() + ")";
	}

	/**
	 * Call when current address changes. Updates the table showing current address's context
	 * information.
	 */
	void updateContextInfo() {
		contextPanelLabel.setTitle(getContextPanelHint());
		contextTableModel.reload();
		updatePreview();
	}

	/**
	 * Call when selecting different context variables or selected address changes. Updates the
	 * previewed context step.
	 */
	private void updatePreview() {
		previewLabel.setText(getPreviewText());
		previewLabel.setSize(previewLabel.getMinimumSize());
		contextPanel.revalidate();
	}

	/**
	 * Call when this panel is being disposed of.
	 */
	public void dispose() {
		contextFilterTable.dispose();
	}

	/**
	 * Add a context register to be included in the previewed context step
	 * 
	 * @param value
	 *            The RegisterValue to be added
	 */
	void addRegister(RegisterValue value) {
		previewContext.add(value);
	}

	/**
	 * Remove a register from being included in the previewed context step
	 * 
	 * @param value
	 *            The Register to remove
	 */
	void removeRegister(RegisterValue value) {
		previewContext.remove(value);
	}

	/**
	 * Returns true if the preview context step contains the given register
	 * 
	 * @param value
	 *            The register to check
	 * @return True if the preview contains the given register, false otherwise
	 */
	boolean containsRegister(RegisterValue value) {
		return previewContext.contains(value);
	}

	/**
	 * Based on mode, return a collection of RegisterValues to be included in the preview
	 */
	private Collection<RegisterValue> getPreviewRegisters() {
		if (mode == Mode.SELECTION) {
			return previewContext;
		}

		HashSet<RegisterValue> out = new HashSet<>();

		Program currentProgram = plugin.getCurrentProgram();

		Register contextReg = currentProgram.getProgramContext().getBaseContextRegister();

		Instruction instruction = currentProgram.getListing()
				.getInstructionAt(plugin.getCurrentAddress());
		if (instruction == null) {
			return out;
		}
		RegisterValue rv = instruction
				.getRegisterValue(contextReg);
		if (rv == null) {
			return out;
		}

		if (mode == Mode.AT_ADDRESS) {
			for (Register reg : rv.getRegister().getChildRegisters()) {
				out.add(rv.getRegisterValue(reg));
			}
		}
		else if (mode == Mode.AT_ADDRESS_COMPACT) {
			out.add(rv);
		}
		else {
			throw new RuntimeException(
				"Got unexpected mode for previewing Context. This should never happen");
		}
		return out;
	}

	/**
	 * Based on mode, return a string representing the currently previewed context step
	 */
	private String getPreviewText() {
		String join = "; ";
		Collection<RegisterValue> previewRegisters = getPreviewRegisters();
		int size = previewRegisters.size();
		if (size == 0) {
			return "";
		}
		if (size > 2) {
			join = ";\n";
		}

		return "`CONTEXT " + previewRegisters.stream()
				.sorted((a, b) -> a.getRegister().getName().compareTo(b.getRegister().getName()))
				.map(x -> x.getRegister().getName() + " = 0x" +
					x.getUnsignedValueIgnoreMask().toString(16))
				.collect(Collectors.joining(join)) +
			"`";
	}

	private void setPreviewMode(Mode mode) {
		this.mode = mode;
		updatePreview();
	}

	/**
	 * A widget providing selection between context preview modes
	 */
	private class ContextPreviewTypeSelector extends ControlPanelWidget {

		private JRadioButton selectionRB;
		private JRadioButton atAddressRB;
		private JRadioButton atAddressCompactRB;

		private ContextHelper contextHelper;

		public ContextPreviewTypeSelector(ContextHelper contextHelper) {
			super("Context Preview Source");
			this.contextHelper = contextHelper;
		}

		@Override
		protected JPanel createContent() {

			JPanel contentPanel = new JPanel();
			contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
			contentPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

			selectionRB = createContextTypeRB(new SelectionAction(), "Selection",
				"When active, the register selections above will be used to create the preview context shown");
			selectionRB.setSelected(true);
			contentPanel.add(selectionRB);

			atAddressRB = createContextTypeRB(new AtAddressAction(), "At Current Address",
				"When active, the context at the current address with unknown bits set to zero will be used to create the preview context shown");
			contentPanel.add(atAddressRB);

			atAddressCompactRB = createContextTypeRB(new AtAddressCompactAction(),
				"At Current Address Compact",
				"When active, the context at the current address with unknown bits set to zero will be used to create the preview context shown. Uses a compact syntax that is more subject to break with future Ghidra versions.");
			contentPanel.add(atAddressCompactRB);

			ButtonGroup group = new ButtonGroup();
			group.add(selectionRB);
			group.add(atAddressRB);
			group.add(atAddressCompactRB);

			return contentPanel;
		}

		private class SelectionAction extends AbstractAction {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				contextHelper.setPreviewMode(Mode.SELECTION);
			}
		}

		private class AtAddressAction extends AbstractAction {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				contextHelper.setPreviewMode(Mode.AT_ADDRESS);
			}
		}

		private class AtAddressCompactAction extends AbstractAction {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				contextHelper.setPreviewMode(Mode.AT_ADDRESS_COMPACT);
			}
		}

		private JRadioButton createContextTypeRB(AbstractAction action, String name,
				String tooltip) {
			GRadioButton button = new GRadioButton(action);
			button.setName(name);
			button.setText(name);
			button.setToolTipText(tooltip);
			button.setAlignmentX(Component.LEFT_ALIGNMENT);
			return button;
		}

	}
}
