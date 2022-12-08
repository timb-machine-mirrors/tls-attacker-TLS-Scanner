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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeWriteEpochAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.result.DtlsReorderingResult;

public class DtlsReorderingProbe
        extends TlsClientProbe<
                ClientScannerConfig, ClientReport, DtlsReorderingResult<ClientReport>> {

    public DtlsReorderingProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.DTLS_REORDERING, scannerConfig);
    }

    @Override
    public DtlsReorderingResult executeTest() {
        return new DtlsReorderingResult(supportsReordering());
    }

    private TestResult supportsReordering() {
        Config config = scannerConfig.createConfig();

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.SERVER);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
        trace.addTlsAction(new ActivateEncryptionAction());
        trace.addTlsAction(new SendAction(new FinishedMessage()));
        trace.addTlsAction(new ChangeWriteEpochAction(0));
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
        GenericReceiveAction receiveAction = new GenericReceiveAction();
        trace.addTlsAction(receiveAction);

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()
                && receiveAction.getReceivedMessages().isEmpty()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return true;
    }

    @Override
    public DtlsReorderingResult getCouldNotExecuteResult() {
        return new DtlsReorderingResult(TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(ClientReport report) {}
}