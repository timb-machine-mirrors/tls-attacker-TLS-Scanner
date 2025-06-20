/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.padding.trace;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.probe.padding.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsscanner.core.probe.padding.vector.PaddingVector;
import java.util.LinkedList;

public class FinishedResumptionPaddingTraceGenerator extends PaddingTraceGenerator {

    /**
     * Constructs a new FinishedResumptionPaddingTraceGenerator with the specified record generator
     * type.
     *
     * @param type The type of padding record generator to use for creating padding vectors
     */
    public FinishedResumptionPaddingTraceGenerator(PaddingRecordGeneratorType type) {
        super(type);
    }

    /**
     * Creates a workflow trace for testing padding oracle vulnerabilities in the Finished message
     * during a session resumption handshake. The padding vector is applied specifically to the
     * record containing the Finished message.
     *
     * @param config The TLS configuration to use for the workflow
     * @param vector The padding vector to apply to the Finished message record
     * @return A workflow trace configured for testing padding oracles in session resumption
     */
    @Override
    public WorkflowTrace getPaddingOracleWorkflowTrace(Config config, PaddingVector vector) {
        RunningModeType runningMode = config.getDefaultRunningMode();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.FULL_RESUMPTION, runningMode);
        if (runningMode == RunningModeType.SERVER) {
            // remove receive Client CCS, FIN
            trace.removeTlsAction(trace.getTlsActions().size() - 1);
        }
        SendAction sendAction = (SendAction) trace.getLastSendingAction();
        LinkedList<Record> recordList = new LinkedList<>();
        for (ProtocolMessage msg : sendAction.getConfiguredMessages()) {
            if (msg instanceof FinishedMessage) {
                recordList.add(vector.createRecord());
            } else {
                recordList.add(new Record(config));
            }
        }
        sendAction.setConfiguredRecords(recordList);
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }
}
