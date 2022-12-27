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
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeConnectionTimeoutAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendMessagesFromLastFlightAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

public class DtlsRetransmissionsProbe extends TlsClientProbe<ClientScannerConfig, ClientReport> {

	private TestResult sendsRetransmissions;
	private TestResult processesRetransmissions;

	public DtlsRetransmissionsProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
		super(executor, TlsProbeType.DTLS_RETRANSMISSIONS, scannerConfig);
		register(TlsAnalyzedProperty.SENDS_RETRANSMISSIONS, TlsAnalyzedProperty.PROCESSES_RETRANSMISSIONS);
	}

	@Override
	public void executeTest() {
		sendsRetransmissions = doesRetransmissions();
		processesRetransmissions = processesRetransmissions();
	}

	private TestResult doesRetransmissions() {
		Config config = scannerConfig.createConfig();
		config.setAddRetransmissionsToWorkflowTraceInDtls(true);
		config.setAcceptContentRewritingDtlsFragments(true);

		WorkflowTrace trace = new WorkflowConfigurationFactory(config)
				.createTlsEntryWorkflowTrace(config.getDefaultServerConnection());
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
		trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage(config)));
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
		trace.addTlsAction(new ChangeConnectionTimeoutAction(3000));
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));

		State state = new State(config, trace);
		executeState(state);
		if (state.getWorkflowTrace().executedAsPlanned()) {
			return TestResults.TRUE;
		} else {
			return TestResults.FALSE;
		}
	}

	private TestResult processesRetransmissions() {
		Config config = scannerConfig.createConfig();
		config.setAddRetransmissionsToWorkflowTraceInDtls(true);
		config.setAcceptContentRewritingDtlsFragments(true);

		WorkflowTrace trace = new WorkflowConfigurationFactory(config)
				.createTlsEntryWorkflowTrace(config.getDefaultServerConnection());
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
		trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage(config)));
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
		trace.addTlsAction(new SendMessagesFromLastFlightAction(1));
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));

		State state = new State(config, trace);
		executeState(state);
		if (state.getWorkflowTrace().executedAsPlanned()) {
			return TestResults.TRUE;
		} else {
			return TestResults.FALSE;
		}
	}

	@Override
	public void adjustConfig(ClientReport report) {
	}

	@Override
	protected void mergeData(ClientReport report) {
		put(TlsAnalyzedProperty.SENDS_RETRANSMISSIONS, sendsRetransmissions);
		put(TlsAnalyzedProperty.PROCESSES_RETRANSMISSIONS, processesRetransmissions);
	}

	@Override
	protected Requirement getRequirements() {
		return Requirement.NO_REQUIREMENT;
	}
}
