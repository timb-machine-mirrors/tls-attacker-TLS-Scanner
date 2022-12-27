/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import java.util.LinkedList;
import java.util.List;

public class CompressionProbe extends TlsClientProbe<ClientScannerConfig, ClientReport> {

	private List<CompressionMethod> supportedCompressions;
	private TestResult forcedCompression;

	public CompressionProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
		super(executor, TlsProbeType.COMPRESSIONS, scannerConfig);
		register(TlsAnalyzedProperty.VULNERABLE_TO_CRIME, TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION,
				TlsAnalyzedProperty.FORCED_COMPRESSION, TlsAnalyzedProperty.SUPPORTED_COMPRESSION_METHODS);
	}

	@Override
	public void executeTest() {
		supportedCompressions = new LinkedList<>();
		for (CompressionMethod compressionMethod : CompressionMethod.values()) {
			LOGGER.debug("Testing compression {}", compressionMethod);

			Config config = scannerConfig.createConfig();
			config.setEnforceSettings(true);
			config.setDefaultServerSupportedCompressionMethods(compressionMethod);
			config.setDefaultSelectedCompressionMethod(compressionMethod);

			WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
			WorkflowTrace workflowTrace = factory.createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.SERVER);
			workflowTrace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

			State state = new State(config, workflowTrace);
			executeState(state);

			if (state.getWorkflowTrace().executedAsPlanned()) {
				supportedCompressions.add(compressionMethod);
			}
		}
		forcedCompression = !supportedCompressions.containsAll(supportedCompressions)
				? forcedCompression = TestResults.TRUE
				: TestResults.FALSE;
	}

	@Override
	public void adjustConfig(ClientReport report) {
		supportedCompressions = report.getClientAdvertisedCompressions();
	}

	@Override
	protected void mergeData(ClientReport report) {
		if (supportedCompressions != null) {
			put(TlsAnalyzedProperty.SUPPORTED_COMPRESSION_METHODS, supportedCompressions);
			if (supportedCompressions.contains(CompressionMethod.LZS)
					|| supportedCompressions.contains(CompressionMethod.DEFLATE)) {
				put(TlsAnalyzedProperty.VULNERABLE_TO_CRIME, TestResults.TRUE);
				put(TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResults.TRUE);
			} else {
				put(TlsAnalyzedProperty.VULNERABLE_TO_CRIME, TestResults.FALSE);
				put(TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResults.FALSE);
			}
		} else {
			put(TlsAnalyzedProperty.VULNERABLE_TO_CRIME, TestResults.COULD_NOT_TEST);
			put(TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResults.COULD_NOT_TEST);
		}
		put(TlsAnalyzedProperty.FORCED_COMPRESSION, forcedCompression);
	}

	@Override
	protected Requirement getRequirements() {
		return new ProbeRequirement(TlsProbeType.BASIC);
	}
}
